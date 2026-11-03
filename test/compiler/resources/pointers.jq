# Cross-check the pointer templates of `ethdebug_resources.json` with the storage layout
# solc emitted for the same contract, given as `--slurpfile layout <Contract>_storage.json`.
#
# Older tables have templates only for composites and use type IDs as pointer IDs.
# Newer tables use layout-qualified IDs and also include scalar templates.

def escaped: gsub("\\("; "$_") | gsub("\\)"; "_$") | gsub(","; "_$_");
def region_names: [.. | objects | select(has("location")) | .name] | unique;

. as $resources
| $layout[0].storage[]
| . as $variable
| (.type | escaped) as $id
| ($resources.types[$id] // error("\($variable.label): no type document for \($id)")) as $type
| ($type.kind == "struct" or $type.kind == "array" or $type.kind == "mapping"
   or (($type.kind == "bytes" or $type.kind == "string") and ($type | has("size") | not))) as $composed
| ($resources.pointers["storage-" + $id] // $resources.pointers[$id]) as $template
| if $composed then
    ($template // error("\($variable.label): no template for \($id)")) as $template
    | "\($variable.label): \($type.kind) template expects \($template.expect | join(" ")), regions \($template.for | region_names | join(" "))"
  elif $template != null and ($template.expect != ["slot", "offset"] or $template.for.location != "storage") then
    error("\($variable.label): invalid scalar storage template")
  else
    "\($variable.label): value type, storage region"
  end
