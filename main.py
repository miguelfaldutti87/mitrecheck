import pyattck

def findEnt(tech_id):
    attack = pyattck.Attck()
    for technique in attack.enterprise.techniques:
        if (tech_id == technique.id):
            for mitigation in technique.mitigations:
                print("Technique Mitigation ID: ", mitigation.id)
                print("Technique Mitigation Name: ", mitigation.name)
    for tool in attack.enterprise.tools:
        for technique in tool.techniques:
            if (tech_id == technique.id):
                print("    Used Tool ID: ",tool.id)
                print("    Used Tool Name: ",tool.name)
                
                
def findMob(tech_id):
    attack = pyattck.Attck()
    for technique in attack.mobile.techniques:
        if (technique.id == tech_id):
            for mitigation in technique.mitigations:
                print("Technique Mitigation ID: ", mitigation.id)
                print("Technique Mitigation Name: ", mitigation.name)
    for tool in attack.mobile.tools:
        for technique in tool.techniques:
            if (tech_id == technique.id):
                print("    Used Tool ID: ",tool.id)
                print("    Used Tool Name: ",tool.name)

def malwareEnterpriseCheck(user_malware):
    attack = pyattck.Attck()  
    for malware in attack.enterprise.malwares:
        if (user_malware.lower() == malware.name.lower()):
            print("Malware ID: ", malware.id)
            for technique in malware.techniques:
                print("Technique ID: ", technique.id)
                print("Technique Name: ",technique.name)
                findEnt(technique.id)
            return True

def malwareMobileCheck(user_malware):
    attack = pyattck.Attck()                       
    for malware in attack.mobile.malwares:
        if (user_malware.lower() == malware.name.lower()):
            print("Malware ID: ", malware.id)
            for technique in malware.techniques:
                print("Technique ID: ", technique.id)
                print("Technique Name: ",technique.name)
                findMob(technique.id)
            return True
    
if __name__ == '__main__':
    user_malware = input("Type MITRE ATT&CK Malware: ")
    malwareEntFound = malwareEnterpriseCheck(user_malware)
    malwareMobFound = malwareMobileCheck(user_malware)
    if not(malwareEntFound) and not(malwareMobFound):
        print("Malware Not Found") 
