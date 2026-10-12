# foundry-unit-test

A Foundry unit test as one trace with three top-level calls, the way Foundry records it:
the deployment of `CounterTest` (steps 0 to 16), `setUp()` (steps 17 to 376), and
`test_Increment()` (steps 377 to 795), tagged `deployment`, `setup`, and `execution` in
`root_kinds`.

Foundry's `--debugger soldb` sends only the test call today, so the three calls were run
as transactions on anvil from Foundry's test sender, which gives the test contract and
`Counter` the addresses `forge test` gives them, traced with `soldb trace --backend replay`,
and joined. Debug info and sources are from `forge test --debug --debugger soldb --dump`
with `dynamic_test_linking = false`, which keeps `new Counter()` from becoming a cheatcode
call. Step memory is dropped and only the `snapshot` copy of each step is kept, to keep the
file small.
