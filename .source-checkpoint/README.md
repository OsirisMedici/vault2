# Source checkpoint

This parentless source snapshot preserves one local workstream without publishing its historical ancestry.

Original source revision: `895e8979bfd62efa028677ebada82b3bf46be22c`.

Private operational documents, credentials, runtime data, generated output and dependencies are excluded. Original licenses, notices, owned code and pinned vendor gitlinks are retained.

CI workflows are retained under `.source-checkpoint/inactive-workflows/` to prevent checkpoint pushes from invoking automation. Ignored standalone build helpers are retained under `.source-checkpoint/ignored-helpers/` when present.

This is source recovery evidence, not a build, deployment or app acceptance. The full path-by-path inclusion and exclusion report is retained locally by the owner.
