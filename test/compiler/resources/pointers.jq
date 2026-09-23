# Cross-check the pointer templates of `ethdebug_resources.json` with the storage layout
# solc emitted for the same contract, given as `--slurpfile layout <Contract>_storage.json`.
#
# One line per variable of the layout, in layout order: a value type has no template and
# is a single region wherever it occurs; a struct, an array, a mapping, `bytes` or `string`
# has the template of its type, keyed like its type document, which expects the base slot
# and, for a mapping, the key. A missing template, or one for a value type, fails.

def escaped: gsub("\\("; "$_") | gsub("\\)"; "_$") | gsub(","; "_$_");
def region_names: [.. | objects | select(has("location")) | .name] | unique;

. as $resources
| $layout[0].storage[]
| . as $variable
| (.type | escaped) as $id
| ($resources.types[$id] // error("\($variable.label): no type document for \($id)")) as $type
| ($type.kind == "struct" or $type.kind == "array" or $type.kind == "mapping"
   or (($type.kind == "bytes" or $type.kind == "string") and ($type | has("size") | not))) as $composed
| if $composed then
    ($resources.pointers[$id] // error("\($variable.label): no template for \($id)")) as $template
    | "\($variable.label): \($type.kind) template expects \($template.expect | join(" ")), regions \($template.for | region_names | join(" "))"
  elif $resources.pointers | has($id) then
    error("\($variable.label): a value type has a template")
  else
    "\($variable.label): value type, no template"
  end
