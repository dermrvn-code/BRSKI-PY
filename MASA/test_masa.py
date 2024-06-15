import requests
import json



import sys
sys.path.append("../") 
from Voucher.voucher import Voucher, parse_voucher, load_certificate, load_public_key

data = {
    "serialnumber" : "8dhewfioiowefojpwef",
    "domain" : "example.com"
}

response  = requests.post(
    'https://localhost:8888/request-voucher', 
    data=json.dumps(data), 
    verify=False, # set to True in production
    cert=('../Registrar/certs/registrar.crt', '../Registrar/certs/registrar_priv.key')
)
voucher_json = response.content


voucher = parse_voucher(voucher_json)
print(json.dumps(voucher.to_dict(), indent=4))

masa_pubkey = load_public_key("../MASA/certs/MASA_pub.key")
registrar_cert = load_certificate("../Registrar/certs/registrar.crt")



if(voucher.verify(masa_pubkey,"example.com", registrar_cert)):
    print("Voucher is valid")
else:
    print("Voucher is invalid")