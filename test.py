from code import TransportAuthority
from police import Police

# Transport authority issues a license with signature.
transport_obj = TransportAuthority()
# Date format: DDMMYYYY
data = {'name': 'Nikunj', 'license_no': 'Dl34321iO', 'issued_on': '21092019', 'valid_till': '21092023'}

t_res = transport_obj.generate_signed_license(data)
print('Issued license with data: {} signature: {}'.format(data, t_res['signature']))

# Police officer verifies license.
# Result should be True.
print('verifying license with data: {} and signature: {}'.format(data, t_res['signature']))
police_obj = Police()
p_res = police_obj.verify_license(data, t_res['signature'])
print('verification status: {}'.format(p_res))

print('########################################')

# Police officer verifies license.
# Result should be False.
data['name'] = 'Aman'
print('verifying license with data: {} and signature: {}'.format(data, t_res['signature']))
police_obj = Police()
p_res = police_obj.verify_license(data, t_res['signature'])
print('verification status: {}'.format(p_res))