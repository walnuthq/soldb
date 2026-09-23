# Check the program-level context of a program against the storage layout of the same
# contract, given as `--slurpfile layout <Contract>_storage.json`, and the pointer
# templates of `ethdebug_resources.json`, given as `--slurpfile resources`.
#
# One line per context variable, in order, saying how its pointer locates it: a value
# type is a region at the layout's slot, a mapping the region of its base slot, any other
# type a reference to the template of the type with the layout's slot bound. A pointer
# that disagrees with the layout or names an unknown template fails with the reason.

def escaped: gsub("\\("; "$_") | gsub("\\)"; "_$") | gsub(","; "_$_");
def hex: ascii_downcase | ltrimstr("0x") | explode
  | reduce .[] as $digit (0; . * 16 + (if $digit >= 97 then $digit - 87 else $digit - 48 end));

.context.variables[]
| . as $variable
| ([$layout[0].storage[] | select(.label == $variable.identifier)] | first) as $entry
| $variable.pointer as $pointer
| if $pointer == null then
    error("\($variable.identifier): no pointer")
  elif $pointer | has("location") then
    if $pointer.location == "transient" then
      "\($variable.identifier): transient region at slot \($pointer.slot)"
    elif ($pointer.slot | hex) != ($entry.slot | tonumber) then
      error("\($variable.identifier): region at slot \($pointer.slot), the layout says \($entry.slot)")
    elif ($entry.type | startswith("t_mapping")) then
      if ($pointer | has("offset")) or ($pointer | has("length")) then
        error("\($variable.identifier): a mapping's base slot is a whole slot")
      else
        "\($variable.identifier): mapping base slot \($pointer.slot)"
      end
    else
      "\($variable.identifier): region at slot \($pointer.slot)"
      + (if $pointer | has("offset") then " offset \($pointer.offset)" else "" end)
      + (if $pointer | has("length") then " length \($pointer.length)" else "" end)
    end
  elif $pointer | has("define") then
    if ($pointer.define.slot | hex) != ($entry.slot | tonumber) then
      error("\($variable.identifier): template bound to slot \($pointer.define.slot), the layout says \($entry.slot)")
    elif $pointer.in.template != ($entry.type | escaped) then
      error("\($variable.identifier): references \($pointer.in.template), its type is \($entry.type | escaped)")
    elif ($resources[0].pointers | has($pointer.in.template) | not) then
      error("\($variable.identifier): references the unknown template \($pointer.in.template)")
    else
      "\($variable.identifier): template \($pointer.in.template) at slot \($pointer.define.slot)"
    end
  else
    error("\($variable.identifier): unexpected pointer shape \($pointer | keys)")
  end
