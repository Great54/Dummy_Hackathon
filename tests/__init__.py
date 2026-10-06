import os

# Discovery tests must never issue live AUTOSAR requests.
os.environ["AUTOSAR_OFFLINE"] = "true"
