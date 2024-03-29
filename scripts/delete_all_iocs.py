import json
import os

from threatfox_censys.threatfox import ThreatFoxClient

# Get the ThreatFox API key from the environment
threatfox_api_key = os.getenv("THREATFOX_API_KEY")
if not threatfox_api_key:
    raise ValueError("ThreatFox API key not found in environment")

# Create a ThreatFoxClient instance
threatfox_client = ThreatFoxClient(api_key=threatfox_api_key)

# Search for IoCs
response = threatfox_client.search_iocs_by_tag("Vshell")
# response = threatfox_client.search_iocs_by_malware("Chaos", limit=10)

# Get data from the response
data = response["data"]

ioc_ids = []

for ioc in data:
    ioc_id = ioc["id"]
    ioc_ids.append(ioc_id)

# Format list as JSON
ioc_ids_json = json.dumps(ioc_ids)

# List javascript
javascript_ids = f"let iocIds = {ioc_ids_json};\n"

# Format script
javascript_functions = """
// Function to send POST request for a single ioc_id
function sendPostRequest(ioc_id) {
    return fetch('https://threatfox.abuse.ch/ajax/', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: `query=delete_ioc&ioc_id=${ioc_id}`
    });
}

// Send POST request for each ioc_id in the list
async function processIds() {
    for (let ioc_id of iocIds) {
        try {
            let response = await sendPostRequest(ioc_id);
            if (!response.ok) {
                console.error(`Failed for ioc_id: ${ioc_id}`);
            } else {
                console.log(`Success for ioc_id: ${ioc_id}`);
            }
        } catch (error) {
            console.error(`Error for ioc_id: ${ioc_id} - ${error.message}`);
        }
    }
}

// Call the function to start processing
processIds();
"""

# Print javascript
print(javascript_ids + javascript_functions)
