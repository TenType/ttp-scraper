import json
from utils import MitreAttack, remap_old_tid, print

def validate_ttp_chains(json_file: str = "ttp-chain-output.json"):
    """Validate TTP chains against MITRE ATT&CK data."""
    
    # Load the TTP chain data
    with open(json_file, "r") as f:
        chains = json.load(f)
        # If a single chain object is provided (not a list), treat it as a singleton list
        if isinstance(chains, dict):
            chains = [chains]
        elif not isinstance(chains, list):
            raise ValueError(f"Unexpected TTP chain format: {type(chains)}")
    
    # Initialize MITRE ATT&CK data
    mitre = MitreAttack()
    
    problems = []
    
    for idx, chain in enumerate(chains):
        chain_num = idx + 1
        
        # Validate goal
        goal = chain.get("goal", {})
        goal_ttp_id = goal.get("ttp_id", "")
        goal_ttp_name = goal.get("ttp_name", "")
        goal_tactic = goal.get("tactic", "")
        
        if not goal_ttp_id:
            problems.append(f"Chain {chain_num}: Missing goal ttp_id")
        else:
            # Remap old TIDs if necessary
            remapped_goal_id = remap_old_tid(goal_ttp_id)
            if remapped_goal_id != goal_ttp_id:
                problems.append(f"Chain {chain_num}: Goal TTP {goal_ttp_id} is deprecated, should be {remapped_goal_id}")
                goal_ttp_id = remapped_goal_id
            
            # Validate goal TTP against MITRE
            mitre_info = mitre.get_mitre_info(goal_ttp_id)
            
            if not mitre_info.get("name"):
                problems.append(f"Chain {chain_num}: Goal TTP {goal_ttp_id} not found in MITRE ATT&CK")
            elif mitre_info["name"] != goal_ttp_name:
                problems.append(f"Chain {chain_num}: Goal TTP name mismatch - Expected '{mitre_info['name']}', got '{goal_ttp_name}'")
            
            # Validate goal tactic
            tactics = mitre_info.get("tactics", [])
            if goal_tactic and tactics:
                if goal_tactic.lower() not in [t.lower() for t in tactics]:
                    problems.append(f"Chain {chain_num}: Goal tactic '{goal_tactic}' not in MITRE tactics {tactics} for {goal_ttp_id}")
            elif not tactics:
                problems.append(f"Chain {chain_num}: Goal TTP {goal_ttp_id} has no tactics in MITRE data")
        
        # Validate TTP chain steps
        ttp_chain = chain.get("TTPChain", [])
        
        if not ttp_chain:
            problems.append(f"Chain {chain_num}: Empty TTPChain")
        
        for step_idx, step in enumerate(ttp_chain):
            step_num = step_idx + 1
            ttp_id = step.get("ttp_id", "")
            ttp_name = step.get("ttp_name", "")
            tactic = step.get("tactic", "")
            order = step.get("order")
            
            # Check order consistency
            if order != step_num:
                problems.append(f"Chain {chain_num}, Step {step_num}: Order field is {order}, expected {step_num}")
            
            if not ttp_id:
                problems.append(f"Chain {chain_num}, Step {step_num}: Missing ttp_id")
                continue
            
            # Remap old TIDs if necessary
            remapped_id = remap_old_tid(ttp_id)
            if remapped_id != ttp_id:
                problems.append(f"Chain {chain_num}, Step {step_num}: TTP {ttp_id} is deprecated, should be {remapped_id}")
                ttp_id = remapped_id
            
            # Validate TTP against MITRE
            mitre_info = mitre.get_mitre_info(ttp_id)
            
            if not mitre_info.get("name"):
                problems.append(f"Chain {chain_num}, Step {step_num}: TTP {ttp_id} not found in MITRE ATT&CK")
            elif mitre_info["name"] != ttp_name:
                problems.append(f"Chain {chain_num}, Step {step_num}: TTP name mismatch - Expected '{mitre_info['name']}', got '{ttp_name}'")
            
            # Validate tactic
            tactics = mitre_info.get("tactics", [])
            if tactic and tactics:
                if tactic.lower().replace(" ", "-") not in [t.lower() for t in tactics]:
                    problems.append(f"Chain {chain_num}, Step {step_num}: Tactic '{tactic}' not in MITRE tactics {tactics} for {ttp_id}")
            elif not tactics:
                problems.append(f"Chain {chain_num}, Step {step_num}: TTP {ttp_id} has no tactics in MITRE data")
            
            if not step.get("action"):
                problems.append(f"Chain {chain_num}, Step {step_num}: Missing action description")
    
    return problems

if __name__ == "__main__":
    problems = validate_ttp_chains()
    
    if problems:
        print(f":x: Found {len(problems)} problems:", style="red")
        for problem in problems:
            print(f"  :warning: {problem}", style="yellow")
    else:
        print(":white_check_mark: All TTP chains are valid!", style="green")
