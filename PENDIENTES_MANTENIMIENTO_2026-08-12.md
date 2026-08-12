# Pendientes de mantenimiento — 2026-08-12

## Resultado de la revisión

No hay código pendiente por portar desde la rama histórica ni desde el stash local:

- `codex/content-hub-cold-memory` conserva el commit `4cd9dd685f290dbc896edf9edfb36e626ea79686` (`perf: raise content hub lambda memory default`). Su parche ya está representado de forma idéntica en `origin/dev` por `6b4c7ec164e39bc8d004c275747a856084916d05`; por eso no debe mezclarse ni rebasarse sobre `dev`.
- El stash `7188feefacbacd04e5533a112c684b60110aa793` (`codex content hub preview unpublished revision`, base `3eafdb02c93f01891462a27ecf09c5a44d42ec74`) se aplicó sin eliminarlo en un worktree aislado. Su comportamiento y su prueba exacta ya fueron incorporados por `10ad94a54492e3f79d84e3a0ec53c4a841b46508` (`fix: resolve content hub preview bundle merge`) y permanecen en `origin/dev` con endurecimientos posteriores.
- La prueba `test_public_bundle_preview_reads_unpublished_revision_package` pasa tanto en el stash aplicado sobre su commit padre como en el `origin/dev` actual.
- La suite completa detectó que Windows no aporta una base IANA a `zoneinfo`; se agregó la dependencia oficial `tzdata` para que la validación de zonas horarias y las pruebas sean portables sin relajar la validación de seguridad.

## Estado preservado deliberadamente

- Repositorio raíz `Z:\GitHub\zoolanding-content-hub`: `HEAD` separado y limpio; no se modificó.
- Rama `codex/content-hub-cold-memory`: se mantiene en su SHA original; no se rebasó, mezcló ni eliminó.
- Stash local: se mantiene intacto; no se hizo `pop` ni `drop`.
- Worktree de inspección `Z:\GitHub\worktrees\content-hub-stash-review-20260812`: queda en `HEAD` separado sobre el padre del stash, con `lambda_function.py` y `tests/test_content_hub_handler.py` modificados por `git stash apply`. Es evidencia reproducible y no debe comitearse ni mezclarse.

## Limpieza futura opcional

Nada de esta sección bloquea el uso o despliegue del repositorio. Si más adelante se desea reducir estado local, primero confirmar que `origin/dev` todavía contiene `6b4c7ec` y `10ad94a`, y que la prueba indicada pasa. Solo después, una persona puede decidir eliminar la rama histórica, el stash y el worktree aislado. No se automatizó esa limpieza para evitar pérdida de trabajo recuperable.
