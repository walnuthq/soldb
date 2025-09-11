    

from .transaction_tracer import TransactionTrace, TransactionTracer
from .colors import bold, dim, address, info, gas_value,warning


def print_contracts_in_transaction(tracer: TransactionTracer,trace: TransactionTrace):
        """Prints the contracts involved in a transaction trace."""
        print(f"Looking for contracts in transaction: {info(trace.tx_hash)} on {info(tracer.rpc_url)}..")
        print(f"\n{bold('Contracts detected in transaction:')}")
        print(dim("-" * 80))

        call_count = 0
        for i, step in enumerate(trace.steps):
            if step.op in ["CALL", "DELEGATECALL", "STATICCALL"]:
                call_count += 1
                
                # Extract call information
                if len(step.stack) >= 6:
                    required_stack_size = 7 if step.op == "CALL" else 6
                    if len(step.stack) >= required_stack_size:
                        to_addr = tracer.extract_address_from_stack(step.stack[-2])
                        calldata = tracer.extract_calldata_from_step(step)

                        # Try to identify target contract
                        target_name = "Unknown"
                        if tracer.multi_contract_parser:
                            target_contract = tracer.multi_contract_parser.get_contract_at_address(to_addr)
                            if target_contract:
                                target_name = target_contract.name
                        
                        # Try to decode function
                        func_name = "Unknown"
                        if calldata and len(calldata) >= 10:
                            selector = calldata[:10]
                            if hasattr(tracer, 'function_signatures'):
                                func_info = tracer.function_signatures.get(selector)
                                if func_info:
                                    func_name = func_info['name']

                        print(f"{address(to_addr)}",end="")
                        if target_name != "Unknown":
                            print(f" ({info(target_name)})")
                        if func_name != "Unknown":
                            print(f"Entry Function: {info(func_name)}",end="")
                        print(f"\nGas: {gas_value(step.gas)}")
                        print(dim("-" * 80))
        
        if call_count == 0:
            print(f"{warning('No contract calls detected in this transaction.')}")
            print(f"Please verify:")
            print(f"  {dim('-')} {'The transaction hash is correct'}")
            print(f"  {dim('-')} {'The RPC URL is correct'}")