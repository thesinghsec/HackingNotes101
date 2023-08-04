#  Initial Internal Attack Strategy
- #### Begin with MITM6 or Responder.
- #### Run scans to generate traffic.
- #### If scans take too long, look for the websites in scope.
- #### Look for default credentials on web logins
    - Printers
    - Jenkins
    - Etc
- #### Think outside the box

# Post-Compromise AD Enumeration
- #### We have compromised a user. Now what?
- #### There are few tools that offer quick and efficient enumeration
     - Bloodhound
     - Plumhound
     - Ldapdomaindump
     - PingCastle
     - And whatever You like.
  

# Post-Compromise Attack Strategy
- #### We have an account, now what?
- #### Search for quick wins:
    - Kerberoasting
    - Secretsdump
    - Pass the Hash/Password
- #### No quick wins? Dig Deep!
    - Enumerate (Bloodhound, etc)
    - Where does the compromised account have access?
    - Old vulnerabilities (Eternal Blue, Print Nightmare, etc)
- #### Think outside the box
