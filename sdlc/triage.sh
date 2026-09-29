#!/bin/sh
# triage.sh -- sort the SDLC / titan-gate files out of Downloads into the repo.
#
# Dry run by default. Nothing moves until you pass --apply.
# Nothing is ever deleted; superseded files go to prompts/archive/.
#
#   ./triage.sh                  # report only
#   ./triage.sh --apply          # actually move
#   ./triage.sh --apply ~/Downloads ~/titan-gate
#
# Why this exists: eight files with overlapping names landed in one folder,
# three of them different versions of the same validator. Validating against
# the wrong copy is silent and looks like success.

APPLY=0
[ "$1" = "--apply" ] && { APPLY=1; shift; }
DL="${1:-$HOME/Downloads}"
DEST="${2:-$HOME/titan-gate}"

[ -d "$DL" ]   || { echo "no such folder: $DL" >&2; exit 2; }
[ -d "$DEST" ] || { echo "no repo at: $DEST  (extract the tarball first)" >&2; exit 2; }

say() { printf '%-46s %-11s %s\n' "$1" "$2" "$3"; }

route() { # route <glob> <action> <subdir> <why>
  # shellcheck disable=SC2086
  for f in $DL/$1; do
    [ -e "$f" ] || continue
    base=$(basename "$f")
    case "$2" in
      keep)
        say "$base" "KEEP" "$4"
        if [ "$APPLY" = 1 ]; then
          mkdir -p "$DEST/$3"
          mv -- "$f" "$DEST/$3/" && echo "    -> $DEST/$3/$base"
        fi ;;
      stale)
        say "$base" "STALE" "$4"
        if [ "$APPLY" = 1 ]; then
          mkdir -p "$DEST/prompts/archive"
          mv -- "$f" "$DEST/prompts/archive/" && echo "    -> archived"
        fi ;;
      inspect)
        say "$base" "INSPECT" "$4"
        if [ "$APPLY" = 1 ]; then
          mkdir -p "$DEST/inbox"
          mv -- "$f" "$DEST/inbox/" && echo "    -> $DEST/inbox/$base"
        fi ;;
    esac
  done
}

echo "Downloads: $DL"
echo "Repo     : $DEST"
[ "$APPLY" = 1 ] && echo "MODE     : APPLY" || echo "MODE     : dry run (pass --apply to move)"
echo
say "FILE" "ACTION" "WHY"
say "----" "------" "---"

route 'MEASUREDSTATE.md'            keep    docs             "source of every R2 [measured:] tag; cite it or delete the number"
route 'MEASURED_STATE.md'           keep    docs             "same, second copy - diff them before trusting either"
route 'SDLC_DESIGNER_v1.*.md'       keep    prompts          "the operating prompt; one source of truth"
route 'response_*.json'             keep    responses        "design audit trail; ./g validate reads these"
route 'test_parser_adversarial.py'  inspect ''               "unknown provenance; candidate agentrepengine_tests - must be shown to FAIL on broken behavior before it counts"
route 'sdlc_designer_system_prompt.md' stale ''              "v1, superseded by v1.1; kept because it is the before-state the FIX list cites"
route 'sdlc-v2*.md'                 stale   ''               "phase table source; keep for reference, work from the Drive copy"
route 'validate_response*.py'       stale   ''               "superseded by evals/validate_response.py inside the repo - three copies is how you validate against the wrong one"
route 'titan*gate*.tar.gz'            stale   ''               "pre-./g build; the repo you extracted replaces it"
route 'titan-gate.tar.gz'           stale   ''               "same"

echo
if [ "$APPLY" = 1 ]; then
  echo "done. now run:  cd $DEST && ./g gate"
else
  echo "nothing moved. rerun with --apply when the table above looks right."
fi
