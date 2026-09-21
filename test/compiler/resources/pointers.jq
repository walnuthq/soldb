# Cross-check the pointer templates of `ethdebug_resources.json` with the storage layout
# solc emitted for the same contract, given as `--slurpfile layout <Contract>_storage.json`.
#
# One line per variable of the layout, in layout order, says how the templates address
# it. A variable no template names, or a variable of value type whose template disagrees
# with the layout about its slot or offset, fails with the reason.

def hex:
  ascii_downcase | ltrimstr("0x") | explode
  | reduce .[] as $digit (0; . * 16 + (if $digit >= 97 then $digit - 87 else $digit - 48 end));

def regions: [.. | objects | select(has("location"))];

# The region names in order of appearance, each once.
def region_names:
  [regions[] | .name] | reduce .[] as $name ([]; if index([$name]) == null then . + [$name] else . end);

def names_variable($label): region_names | any(. == $label or startswith($label + "-"));

# A variable of value type is one region at the layout's slot. The region's offset counts
# from the most significant byte of the slot and the layout's from the least significant
# one, so a value of `length` bytes at layout offset `o` starts at byte `32 - o - length`.
# A region without a length covers the rest of its slot, and one whose length exceeds a
# slot starts at the beginning of the first one and continues into those that follow.
def check_region($variable; $template):
  if (.slot | type) != "string" then
    error("\($variable.label): \($template) computes its slot, the layout gives one")
  elif (.slot | hex) != ($variable.slot | tonumber) then
    error("\($variable.label): \($template) addresses slot \(.slot), the layout says \($variable.slot)")
  elif has("length") and (.length | hex) >= 32 and (((.offset // "0x00") | hex) != 0 or $variable.offset != 0) then
    error("\($variable.label): \($template) spans whole slots but starts at an offset")
  elif has("length") and (.length | hex) < 32 and ((.offset // "0x00") | hex) + (.length | hex) + $variable.offset != 32 then
    error("\($variable.label): \($template) covers bytes \(.offset // "0x00")+\(.length), the layout says offset \($variable.offset)")
  elif (has("length") | not) and ($variable.offset != 0 or has("offset")) then
    error("\($variable.label): \($template) is a whole word, the layout says offset \($variable.offset)")
  else
    "region at slot \($variable.slot)"
    + (if has("offset") then " offset \(.offset | hex)" else "" end)
    + (if has("length") then ", length \(.length | hex)" else "" end)
  end;

def describe($variable; $template):
  if (.expect | length) > 0 then "keyed by \(.expect | join(" "))"
  elif (.for | has("location")) then (.for | check_region($variable; $template))
  elif (.for | has("group")) then "group of \(.for | region_names | join(" "))"
  elif (.for | has("list")) then "list of \(.for | region_names | join(" "))"
  else error("\($variable.label): \($template) has an unexpected shape \(.for | keys)")
  end;

. as $resources
| $layout[0].storage[]
| . as $variable
# The template name ends with the variable's AST ID; an inherited variable has one
# template per contract inheriting it, all of which must agree with this layout.
| [
    $resources.pointers
    | to_entries[]
    | select(.key | endswith("_\($variable.astId)"))
    | select(.value.for | names_variable($variable.label))
    | . as $entry
    | ($entry.value | describe($variable; $entry.key))
  ]
| unique
| if length == 0 then error("\($variable.label): no pointer template names it")
  elif length > 1 then error("\($variable.label): its templates disagree: \(join("; "))")
  else "\($variable.label): \(.[0])"
  end
