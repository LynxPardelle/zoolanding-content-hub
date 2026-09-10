"""Small exact-key DynamoDB double with atomic conditional commits.

Only the documented expression subset emitted by THN finalization is accepted.
Unknown syntax or operations fail the test rather than silently succeeding.
"""
from copy import deepcopy
import re
from botocore.exceptions import ClientError
from botocore.session import Session
from botocore.validate import validate_parameters
from content_hub_v2_registry_fence import marshal_item, unmarshal_item

MISSING=object()
TRANSACTION_SHAPE=Session().get_service_model("dynamodb").operation_model("TransactWriteItems").input_shape


def matches(expression,item,names,values):
    tokens=re.findall(r"(?:#[A-Za-z0-9_]+|[A-Za-z][A-Za-z0-9_]*)(?:\.(?:#[A-Za-z0-9_]+|[A-Za-z][A-Za-z0-9_]*))*|:[A-Za-z0-9_]+|[(),=>]",expression)
    assert re.sub(r"\s+","",expression)=="".join(tokens),expression
    position=0
    def take(expected=None):
        nonlocal position
        token=tokens[position];position+=1
        if expected is not None: assert token==expected,(token,expected)
        return token
    def resolve(token):
        if token.startswith(":"): return values[token]
        result=item or {}
        for field in token.split('.'):
            result=result.get(names.get(field,field),MISSING) if isinstance(result,dict) else MISSING
        return result
    def atom():
        token=take()
        if token=="(":
            result=disjunction();take(")");return result
        if token in ("attribute_not_exists","attribute_exists","attribute_type"):
            take("(");value=resolve(take())
            if token=="attribute_type":
                take(",");kind=resolve(take());result=value is None and kind=="NULL"
            else: result=(value is MISSING) == (token=="attribute_not_exists")
            take(")");return result
        left=resolve(token);operator=take();right=resolve(take())
        if left is MISSING or right is MISSING: return False
        if operator=="=": return left==right
        if operator==">": return left>right
        raise AssertionError(operator)
    def conjunction():
        result=atom()
        while position<len(tokens) and tokens[position]=="AND":
            take();other=atom();result=result and other
        return result
    def disjunction():
        result=conjunction()
        while position<len(tokens) and tokens[position]=="OR":
            take();other=conjunction();result=result or other
        return result
    result=disjunction();assert position==len(tokens),expression
    return result


class AtomicDynamo:
    def __init__(self):
        self.items={};self.calls=[];self.before_commit=None

    @staticmethod
    def identity(table,key):
        return table,tuple(sorted(key.items()))

    @staticmethod
    def key(item):
        return {"sessionIdHash":item["sessionIdHash"]} if "sessionIdHash" in item else {k:item[k] for k in ("pk","sk")}

    def seed(self,table,item):
        self.items[self.identity(table,self.key(item))]=deepcopy(item)

    def row(self,table,key):
        return self.items.get(self.identity(table,key))

    def get_item(self,**kwargs):
        assert kwargs.get("ConsistentRead") is True
        assert "SessionV2" not in kwargs["TableName"],"publisher cannot read sessions"
        self.calls.append(("get",deepcopy(kwargs)))
        row=self.row(kwargs["TableName"],unmarshal_item(kwargs["Key"]))
        return {"Item":marshal_item(row)} if row is not None else {}

    def transact_write_items(self,**kwargs):
        validate_parameters(kwargs,TRANSACTION_SHAPE)
        self.calls.append(("transaction",deepcopy(kwargs)))
        if self.before_commit:
            hook,self.before_commit=self.before_commit,None
            hook(self)
        targets=[];pending=[]
        for operation in kwargs["TransactItems"]:
            assert len(operation)==1
            kind,body=next(iter(operation.items()))
            assert kind in ("ConditionCheck","Put","Delete","Update"),kind
            assert "ReturnValuesOnConditionCheckFailure" not in body
            row=unmarshal_item(body["Item"]) if kind=="Put" else None
            key=self.key(row) if row is not None else unmarshal_item(body["Key"])
            identity=self.identity(body["TableName"],key)
            targets.append(identity)
            if not matches(body["ConditionExpression"],self.items.get(identity),body.get("ExpressionAttributeNames",{}),
                           unmarshal_item(body.get("ExpressionAttributeValues",{}))):
                raise ClientError({"Error":{"Code":"TransactionCanceledException"}},"TransactWriteItems")
            if kind=='Update':
                assert body['UpdateExpression']=='SET receipts.#object = :receipt'
                row=deepcopy(self.items[identity])
                row['receipts'][body['ExpressionAttributeNames']['#object']]=unmarshal_item(body['ExpressionAttributeValues'])[':receipt']
            if kind!="ConditionCheck": pending.append((identity,row))
        assert len(targets)==len(set(targets)),"duplicate transaction targets"
        assert len(targets)<=90
        for identity,row in pending:
            if row is None: self.items.pop(identity,None)
            else: self.items[identity]=deepcopy(row)
        return {}
