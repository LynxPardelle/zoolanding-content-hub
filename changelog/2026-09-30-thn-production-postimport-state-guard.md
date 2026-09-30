# THN production Content Hub post-import state guard

The protected import run `36770527852` completed with four retained resources attached to the existing Content Hub stack. AWS reported `IMPORT_COMPLETE`, 21 resources, unchanged identities for the previous 17, and `IN_SYNC` drift with zero deviations. No routes were activated.

The first protected `purpose=state` review now requires that exact 21-resource imported baseline and the approved live Registry policy revision and digest. Its candidate preserves all four imported declarations and the existing public API; the native change set may only add new THN resources. Review and execution recapture the imported resource settings and reject any modification, removal, or replacement of an existing resource before execution.

Focused red/green tests cover missing or replaced imports, the live policy fingerprint, candidate preservation, native inventory rejection, and CloudFormation's nullable replacement marker on additions. The full local suite ran 544 tests with 5 skips and 0 failures. The fresh production projection matched the prior projection. A read-only AWS snapshot passed the new baseline validator, and local SAM translation of the state candidate preserved all 21 existing native definitions while adding only new THN definitions. This is code only until a separate protected state review and exact digest approval.
