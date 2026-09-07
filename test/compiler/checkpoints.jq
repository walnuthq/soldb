# Select named source checkpoints without changing the compiler input bytes.
gsub("\r\n|\r"; "\n")
| split("\n")
| to_entries
| map(
    select(.value | contains("// debug-check:"))
    | {
        key: (.value | split("// debug-check:")[1] | gsub("^\\s+|\\s+$"; "")),
        value: {source: $source, line: (.key + 1)}
      }
  )
| if any(.[]; .key == "") then error("empty checkpoint name")
  elif length != (map(.key) | unique | length) then error("duplicate checkpoint name")
  else from_entries
  end
| . as $checkpoints
| $names
| map(
    . as $name
    | if $checkpoints | has($name) then $checkpoints[$name]
      else error("unknown checkpoint: \($name)")
      end
  )
