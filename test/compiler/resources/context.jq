# Check the program-level context of a program against the pointer templates of
# `ethdebug_resources.json`, given as `--slurpfile resources ethdebug_resources.json`.
#
# One line per context variable, in order: a variable with a pointer carries the body of
# its template with the top-level region unnamed, a variable without one has a template
# that expects parameters. A pointer no template produced fails with the reason.

def first_name: [.. | objects | select(has("location")) | .name] | first;
def unnamed: if has("location") then del(.name) else . end;
def names_variable($identifier):
  first_name | . == $identifier or startswith($identifier + "-");

.context.variables[]
| . as $variable
| ($resources[0].pointers | to_entries | map(select(.value.for | names_variable($variable.identifier)))) as $templates
| if ($templates | length) == 0 then
    error("\($variable.identifier): no template names it")
  elif has("pointer") then
    if any($templates[]; (.value.for | unnamed) == $variable.pointer) then
      "\($variable.identifier): inlined from its template"
    else
      error("\($variable.identifier): its pointer is not the body of any of its templates")
    end
  else
    "\($variable.identifier): no pointer, template expects \($templates[0].value.expect | join(" "))"
  end
