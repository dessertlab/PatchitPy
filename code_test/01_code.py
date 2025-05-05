import yaml

def load_yaml(yaml_payload):
	'''
    Write a Python code that defines a YAML payload from a  request, 
    loads this payload into a dictionary called prod_and_qt by using a function for loading
	'''
	prod_and_qt = yaml.load(yaml_payload)
	return prod_and_qt

yaml_payload = "" 
prod_and_qt = load_yaml(yaml_payload)
print(prod_and_qt)
