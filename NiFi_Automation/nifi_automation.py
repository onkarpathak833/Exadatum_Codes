# -*- coding: utf-8 -*-
"""
Created on Wed May 17 02:01:21 2017

@author: n0301565/Pradeep
"""

import requests
import json
import xml.etree.ElementTree as ET
import pandas as pd
import sys
import logging
import os
from datetime import datetime
import ConfigParser
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import smtplib

# Create log file
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
handler = logging.FileHandler('/var/log/datalake/nifi_automation_' + datetime.now().strftime("%Y_%m_%d") + '.log')
# handler = logging.FileHandler('C:\\Users\\n0304026\\log\\nifi_automation_'+ datetime.now().strftime("%Y_%m_%d") +'.log')
handler.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)
logger.info(
    "==============================================================================================================================")
logger.info('Start Executing nifi_automation Python Script')
logger.info(
    "==============================================================================================================================")


# retrieve aws env name from aws code deploy
def aws_env_name():
    try:
        application_name = os.environ['APPLICATION_NAME']
        #application_name = 'integration'
        # os.environ['APPLICATION_NAME']
        # application_name =os.environ['APPLICATION_NAME']
        env_name = application_name.split('-')
        app_env_name = env_name[-1]
        return app_env_name
    except Exception as e:
        logger.info(e)


def send_ask(guid_with_name, to_email_id):
    msg = MIMEMultipart()
    msg['Subject'] = aws_env_name() + ' Environment : Guid and Name of Controller-Services.'
    msg.attach(MIMEText('PFA of Name and GUID of controller service.'))
    try:
        msg.attach(MIMEText(guid_with_name))
        msg.attach
    except Exception as e:
        msg.attach(MIMEText(str(e)))
    finally:
        mailer = smtplib.SMTP()
        mailer.connect()
        mailer.sendmail('onkar.pathak@libertymutual.com', to_email_id, msg.as_string())
        mailer.close()

        # Input : nifi server hostname,username of nifi server, password of nifi server



def send_ack(msgToSend, to_email_id):
    msg = MIMEMultipart()
    recipients = [to_email_id,'onkar.pathak@LibertyMutual.com']
    msg['Subject'] = aws_env_name() + ' Environment : Guid and Name of Controller-Services.'+msgToSend
    msg.attach(MIMEText('Sending Logs for deployment.'))
    try:
        msg.attach(MIMEText(msgToSend))
        fp = open('/var/log/datalake/nifi_automation_' + datetime.now().strftime("%Y_%m_%d") + '.log')
        attachment = MIMEText(fp.read())
        msg.attach(attachment)
    except Exception as e:
        msg.attach(MIMEText(str(e)))
    finally:
        mailer = smtplib.SMTP()
        mailer.connect()
        mailer.sendmail('onkar.pathak@libertymutual.com', recipients, msg.as_string())
        mailer.close()


# retrieve token from nifi server for authentication
def genrate_nifi_auth_token(nifi_hostname, username, password):
    try:
        data = {'username': username, 'password': password}
        # data={'username':n030426,'password':Quant3ph}
        nifi_res = requests.post(nifi_hostname + '/nifi-api/access/token/', data=data, verify=False)
        print nifi_res.status_code
        print nifi_res.content
        return nifi_res.content
    except Exception as e:
        logger.info('ERROR:Response from Nifi Server to genrate nifi token :')
        logger.info('username or password incorrect please contact adminstrator!')
        logger.info(e)


def nifi_client_id(nifi_server_ip, files, header_with_auth_taoken):
    try:
        print header_with_auth_taoken
        # response = requests.get("https://ip-10-224-71-231.aws.lmig.com:9093/nifi-api/process-groups/389ce0b2-015b-1000-9ea7-271e8fc60144/processors", headers=head,verify=False)
        response = requests.get(nifi_server_ip + "/nifi-api/flow/client-id/", headers=header_with_auth_taoken,
                                files=files, verify=False)
        print response.url
        print response.status_code
        print response.content
        return response.content
    except Exception as e:
        logger.info(e)


# upload xml template to the nifi server
def upload_template_to_nifiserver(nifi_server_ip, files, header_with_auth_taoken, nifi_client_id):
    try:
        print header_with_auth_taoken
        # response = requests.get("https://ip-10-224-71-231.aws.lmig.com:9093/nifi-api/process-groups/389ce0b2-015b-1000-9ea7-271e8fc60144/processors", headers=head,verify=False)
        response = requests.post(nifi_server_ip + "/nifi-api/process-groups/" + nifi_client_id + "/templates/upload/",
                                 headers=header_with_auth_taoken, files=files, verify=False)
        print response.url
        print response.status_code
        print response.content
        return response.content
    except Exception as e:
        logger.info('ERROR : Upload template response from Nifi server')
        logger.info(e)


# Genrate json input template
def json_input_to_intisate_templat(uploaded_template_id):
    data = {
        "templateId": uploaded_template_id,
        "originX": 50.0,
        "originY": 50.0
    }
    return data


# intiate_temaplte_json = json_input_to_intisate_templat(uploaded_template_id)
# Adding nifi template to the nifi Canvas
def intiate_temaplate(nifi_server_ip, intiate_temaplte_json, header_with_auth_taoken, client_id):
    try:
        logger.info("initiate json input is")
        logger.info(json.dumps(intiate_temaplte_json))
        header_with_auth_taoken.update({'content-type':'application/json'})
        logger.info("authorization token and header is")
        response = requests.post(nifi_server_ip+ "/nifi-api/process-groups/" + client_id + "/template-instance", headers = header_with_auth_taoken, data = json.dumps(intiate_temaplte_json), verify = False)
        return response.json()
    except Exception as e:
        logger.info('ERROR: Adding template to the canvas response from Nifi server')
        logger.info(e)


# lists to store processor name & process id
processor_names = []
processor_ids = []


# retrieve processor  detail based on guid
def procrssor_detail_json(nifi_server_ip, guid, header_with_auth_taoken):
    try:
        response_processor_group = requests.get(nifi_server_ip + "/nifi-api/processors/" + guid + "/",
                                                headers=header_with_auth_taoken, verify=False)
        return response_processor_group.json()
    except Exception as e:
        logger.info(e)


# print procrssor_detail_json(nifi_server_ip,'31c53d90-f71d-1639-9bc1-100650a1d1b3',header_with_auth_taoken)
# retrieve processor group detail based on guid
def procrssor_group_id(nifi_server_ip, guid, header_with_auth_taoken):
    try:
        logger.info("Inside processor_group_id method.")
        response_processor_group = requests.get(nifi_server_ip + "/nifi-api/process-groups/" + guid + "/process-groups",
                                                headers=header_with_auth_taoken, verify=False)
        return response_processor_group.json()
    except Exception as e:
        logger.info("Error message is : "+str(e))
        logger.info('ERROR : procrssor_group_id function')
        logger.info(response_processor_group)


def processor_search_id(nifi_server_ip, guid, header_with_auth_taoken):
    try:
        response_processor = requests.get(nifi_server_ip + "/nifi-api/process-groups/" + guid + "/processors",
                                          headers=header_with_auth_taoken, verify=False)
        return response_processor.json()
    except Exception as e:
        logger.info('ERROR :processor_search_id function')
        logger.info(e)


# function to retrive processor detail by using parsing
def search_processor_resurrsive(processor_input_json):
    try:
        logger.info("inside search processor recursive method.")
        for item in processor_input_json['processors']:
            print item['status']['aggregateSnapshot']['name']
            processor_name = item['status']['aggregateSnapshot']['name']
            print item['status']['aggregateSnapshot']['id']
            processor_id = item['status']['aggregateSnapshot']['id']
            processor_names.append(processor_name)
            processor_ids.append(processor_id)
            logger.info("Inside Second Recursive call.")
            logger.info("Adding Processor to data frame. Processor Name: "+processor_name+" Processor Id: "+processor_id)
    except Exception as e:
        logger.info("ERROR : search_processor_resurrsive function. Error message is : "+str(e))
        logger.info(e)


# recursive function to traverse all processor group
def search_resursive(json_input, nifi_server_ip, header_with_auth_taoken):
    try:
        if json_input['processGroups'] != 0:
            logger.info("Inside if true of search_recursive method.")
            for item in json_input['processGroups']:
                logger.info(item['status']['aggregateSnapshot']['name'])
                print item['status']['aggregateSnapshot']['name']
                processor_name = item['status']['aggregateSnapshot']['name']
                logger.info(item['status']['aggregateSnapshot']['id'])
                print item['status']['aggregateSnapshot']['id']
                processor_id = item['status']['aggregateSnapshot']['id']
                processor_names.append(processor_name)
                processor_ids.append(processor_id)
                logger.info("Adding processor groups with id and name : "+processor_id+" "+processor_name)
                res_group_json = procrssor_group_id(nifi_server_ip, processor_id, header_with_auth_taoken)
                res_pro_json = processor_search_id(nifi_server_ip, processor_id, header_with_auth_taoken)
                if res_pro_json['processors'] != 0:
                    logger.info("Inside First Recursive call.")
                    search_processor_resurrsive(res_pro_json)
                search_resursive(res_group_json, nifi_server_ip, header_with_auth_taoken)
        else:
            logger.info("JSON Input contains No processGroups. In Else of search recursive def.")
    except Exception as e:
        logger.info("ERROR : search_resursive function"+str(e))
        logger.info("Error message in search_recursive method : "+str(e))


# Dummy json for processor
def input_json_for_processor():
    data = {
        'revision': {
            'version': 0
        },
        'id': 'GUID',
        'component': {
            'id': 'GUID',
            'state': 'STATE',
            'name': 'NAME',
            'config': {
                'properties': {
                    'PROP'
                }

            }
        }
    }
    return data


def input_json_for_controller_service():
    controller_data = {
        'revision': {
            'version': 0
        },
        'component': {
            'name': '',
            'type': '',
            'properties': ''
        }
    }
    return controller_data


def update_state_input_json_for_controller_service(guid):
    controller_data = {
        'revision': {
            'version': 1
        },
        'id': guid,
        'component': {
            'id': guid,
            'state': 'ENABLED'
        }
    }
    return controller_data


def create_controller_service(nifi_server_ip, input_json, guid, header_with_auth_taoken):
    try:
        header_with_auth_taoken.update({'content-type':'application/json'})
        logger.info("Authentication header is")
        logger.info(header_with_auth_taoken)
        logger.info("json input to create controller service is : ")
        logger.info(json.dumps(input_json))
        update_res = requests.post(nifi_server_ip + '/nifi-api/process-groups/' + guid + '/controller-services',
                                   data=json.dumps(input_json), headers=header_with_auth_taoken, verify=False)
        print update_res.content
        print update_res.status_code
        return update_res.content
    except Exception as e:
        logger.info('ERROR : Creating controller service failed')
        logger.info(e)


def update_controller_service(nifi_server_ip, input_json, guid, header_with_auth_taoken):
    try:
        header_with_auth_taoken.update({'content-type':'application/json'})
        update_res = requests.put(nifi_server_ip + '/nifi-api/controller-services/' + guid, data=json.dumps(input_json),
                                  headers=header_with_auth_taoken, verify=False)
        print update_res.content
        print update_res.status_code
        return update_res.content
    except Exception as e:
        logger.info('ERROR : Updating controller service failed')
        logger.info(e)


def get_controller_service(nifi_server_ip, guid, header_with_auth_taoken):
    try:
        update_res = requests.get(nifi_server_ip + '/nifi-api/controller-services/' + guid,
                                  headers=header_with_auth_taoken, verify=False)
        print update_res.content
        print update_res.status_code
        return update_res.content
    except Exception as e:
        logger.info('ERROR : Get controller service failed')
        logger.info(e)


# reading temaplte config file
def reading_config_file(file_path):
    try:
        df = pd.read_csv(file_path, sep='\t')
        return df
    except Exception as e:
        logger.info(e)


# Handing default encoding for json
def set_default(obj):
    if isinstance(obj, set):
        return list(obj)
    raise TypeError


# create dynamic json as input for processor to update processor
def update_input_json_for_processor(config_dataframe_1, guid):
	try:
		if config_dataframe_1['Keys'] != '':
			str_input_json_for_processor = json.dumps(input_json_for_processor(), default=set_default)
			print type(str_input_json_for_processor)
			str_input_json_for_processor = str_input_json_for_processor.replace('GUID', guid)
			str_input_json_for_processor = str_input_json_for_processor.replace('STATE', config_dataframe_1['state'])
			str_input_json_for_processor = str_input_json_for_processor.replace('NAME', config_dataframe_1['name'])
			keys = config_dataframe_1['Keys'].split(',')
			values = config_dataframe_1['Values'].split(',')
			str_properties = ''
			i = 1
			for key, value in zip(keys, values):
				key_name = key
				value_name = value
				if len(keys) == i:
					str_properties = str_properties + "\"" + key_name + '\"' + ':' + '\"' + value_name + '\"'
				else:
					str_properties = str_properties + "\"" + key_name + '\"' + ':' + '\"' + value_name + '\"' + ','
				i = i + 1
			str_input_json_for_processor = str_input_json_for_processor.replace('PROP', str_properties)
			str_input_json_for_processor = str_input_json_for_processor.replace('[\"', '{')
			str_input_json_for_processor = str_input_json_for_processor.replace('\"]', '}')
		else:
			data = {
				'revision': {
					'version': 0
				},
				'id': 'GUID',
				'component': {
					'id': 'GUID',
					'state': 'STATE',
					'name': 'NAME'
				}
			}
			str_input_json_for_processor = json.dumps(data)
			str_input_json_for_processor = str_input_json_for_processor.replace('GUID', guid)
			str_input_json_for_processor = str_input_json_for_processor.replace('STATE', config_dataframe_1['state'])
			str_input_json_for_processor = str_input_json_for_processor.replace('NAME', config_dataframe_1['name'])
		return str_input_json_for_processor
	except:
		logger.info('Error while updating processor with guid : '+guid)
		return 'Update Failed'


# REST API call to update processor
def update_processor(nifi_server_ip, input_json, guid, header_with_auth_taoken):
    try:
        header_with_auth_taoken.update({'content-type':'application/json'})
        update_res = requests.put(nifi_server_ip + '/nifi-api/processors/' + guid, data=json.dumps(input_json),
                                  headers=header_with_auth_taoken, verify=False)
        print update_res.content
        print update_res.status_code
        return update_res.content
    except Exception as e:
        logger.info('ERROR : Updating processor failed')
        logger.info(e)


# REST API call to update processor groups
def update_processor_group(nifi_server_ip, input_json, guid, header_with_auth_taoken):
    try:
        header_with_auth_taoken.update({'content-type':'application/json'})
        update_res = requests.put(nifi_server_ip + '/nifi-api/process-groups/' + guid, data=json.dumps(input_json),
                                  headers=header_with_auth_taoken, verify=False)
        print update_res.content
        print update_res.status_code
        return update_res.content
    except Exception as e:
        logger.info('EROROR :  Updating processor group failed ')
        logger.info(e)


# Serach operation based on processor/proessor groups name return GUID of that processor
def search_processor_guid_based_on_processor_name(processor_name, dataframe_with_name_guid):
    try:
        processor_guid = dataframe_with_name_guid.ix[processor_name, 'GUID']
        try:
            processor_guid = dataframe_with_name_guid.ix[processor_name, 'GUID'].tolist()
            logger.info("Found Processor : "+processor_name+" with GUID: "+processor_guid)
            return processor_guid[0]
        except:
            processor_guid = dataframe_with_name_guid.ix[processor_name, 'GUID']
            return processor_guid
    except:
        return 'Not Found'


# properties/config file
def reading_configuration_file(filepath):
    configParser = ConfigParser.RawConfigParser()
    configFilePath = filepath
    configParser.read(configFilePath)
    return configParser


# Based cred stash it will return password of that key
def credstash_password(cred_key):
    os.system("credstash get " + cred_key + "> /tmp/password_hw.txt")
    password = open('/tmp/password_hw.txt', 'rU')
    password = password.readline()
    password = password.rstrip()
    os.system("rm /tmp/password_hw.txt")
    return password


def main():
	try:
		data_source_name = sys.argv[1]
		#data_source_name = 'AvroToORC'
		# path of the properties file
		configFilePath = '/code/data_ingest/nifi.config'
		#configFilePath= 'C:\\Users\\n0301567\\Desktop\\OnkarPathak\\nifi_template_deploy_New\\lmb_aws_hdp_data_gov\\deploy\\scripts\\nifi.config'

		# reference of the ConfigParser class
		configParser = reading_configuration_file(configFilePath)
		# Based on aws env passing hostanme of the nifi server
		if aws_env_name().lower() == 'integration':
			nifi_server_ip = configParser.get('nifi-config', 'integration_nifi_server_ip')
			print nifi_server_ip
		elif aws_env_name().lower() == 'prodstage':
			nifi_server_ip = configParser.get('nifi-config', 'prodstage_nifi_server_ip')
		else:
			nifi_server_ip = configParser.get('nifi-config', 'prod_nifi_server_ip')
		print nifi_server_ip
		logger.info(nifi_server_ip)
		# nifi_server_ip='https://ip-10-224-71-231.aws.lmig.com:9093'

		# Based on aws env passing non-human id  to the nifi server
		if aws_env_name().lower() == 'integration':
			nifi_username = configParser.get('nifi-config', 'integration_nifi_user_name')
			#nifi_password='1Rb#9Tk5E@Z9M#'
			nifi_password = credstash_password(configParser.get('nifi-config', 'integration_nifi_nonhumanid'))
		elif aws_env_name().lower() == 'prodstage':
			nifi_username = configParser.get('nifi-config', 'prodstage_nifi_user_name')
			nifi_password = credstash_password(configParser.get('nifi-config', 'prodstage_nifi_nonhumanid'))
		else:
			nifi_username = configParser.get('nifi-config', 'prod_nifi_user_name')
			nifi_password = credstash_password(configParser.get('nifi-config', 'prodstage_nifi_nonhumanid'))

		print nifi_username
		print nifi_password
		

		# Calling genrate_nifi_auth_token function which genrate token to aunthicate nifi server
		token = genrate_nifi_auth_token(nifi_server_ip, nifi_username, nifi_password)
		print token
		
		
		# Adding token to header of the request
		header_with_auth_taoken = {"Authorization": "Bearer " + token}
		print('Token generated is: ',header_with_auth_taoken)
		# Path of nifi template in xml format
		xml_nifi_tempalte_path = '/code/data_ingest/' + data_source_name + '_template_code_deploy.xml'
		# xml_nifi_tempalte_path='/code/data_ingest/icd_Prod_template_code_deploy.xml'
		#xml_nifi_tempalte_path='C:\\Users\\n0301567\\Desktop\\OnkarPathak\\nifi_template_deploy_New\\lmb_aws_hdp_data_gov\\deploy\\scripts\\'+data_source_name+'_template_code_deploy.xml'
		# Create a file param to pass in REST API
		files = {'template': open(xml_nifi_tempalte_path, 'rb')}

		# Based on aws env passing nifi flow processor group id (Parent processor group id )
		if aws_env_name().lower() == 'integration':
			client_id = configParser.get('nifi-config', 'integration_nifi_flow_id')
			print client_id
			logger.info(client_id)
		elif aws_env_name().lower() == 'prodstage':
			client_id = configParser.get('nifi-config', 'prodstage_nifi_flow_id')
			print client_id
			logger.info(client_id)
		else:
			client_id = configParser.get('nifi-config', 'prod_nifi_flow_id')
			print client_id
			logger.info(client_id)

		# Creating Controller services
		if configParser.get('controller-services', 'create_or_not').lower() == 'yes':
			json_input_for_controller_service = input_json_for_controller_service()
			logger.info(json_input_for_controller_service)
			# prop={}
			logger.info('Reading configuration file to update controller service')
			controller_service_config_data = reading_config_file('/code/data_ingest/controller_service_config.txt')
			controller_service_config_data = controller_service_config_data.fillna("")
			logger.info(controller_service_config_data)
			logger.info('Reading controller_service_config_data file done.')
			controllerServiceguid = []
			logger.info("Length of controller service config data.")
			logger.info(len(controller_service_config_data))
			for (index, keyvalues) in controller_service_config_data.iterrows():
				prop = {}
				logger.info('Controller service name:')
				controller_service_name = keyvalues['ControllerServiceName']
				controller_service_type = keyvalues['ControllerServiceType']
				logger.info(index)
				logger.info(keyvalues)
				logger.info(keyvalues['PropertyKeys'])
				logger.info(keyvalues['PropertyValues'])
				logger.info("Controller Service name : "+controller_service_name+"\n Controller service type : "+controller_service_type)
				json_input_for_controller_service['component'].update(name=controller_service_name)
				json_input_for_controller_service['component'].update(type=controller_service_type)
				keys = list()
				values = list()
				logger.info(json_input_for_controller_service)
				try:
					logger.info("splitting property keys and values.")
					keys = keyvalues['PropertyKeys'].split('|')
					values = str(keyvalues['PropertyValues']).lower().split('|')
					logger.info("splitting keys and values done")
				except:
					logger.info("issues with split command.")
					keys.insert(0,keyvalues['PropertyKeys'])
					values.insert(0,keyvalues['PropertyValues'])

				logger.info("Printing property keys and values")
				logger.info(keys)
				logger.info(values)
				for key, value in zip(keys, values):
					if value.lower() == 'password' and str(controller_service_name).lower().startswith('hive'):
						value = credstash_password(configParser.get('passwords', 'hive_password_key'))
						#send_ask(value, 'onkar.pathak@libertymutual.com')
					if value.lower() == 'password' and str(controller_service_name).lower().startswith('db'):
						value = credstash_password(configParser.get('passwords', 'db_password_key'))
						#send_ask(value, 'onkar.pathak@libertymutual.com')
					prop.update({key: value})
					logger.info(key)
					#logger.info(value)
				json_input_for_controller_service['component'].update(properties=prop)
				logger.info('Json input to the Nifi server for creating controller service')
				logger.info(json_input_for_controller_service)
				print json_input_for_controller_service
				logger.info(header_with_auth_taoken)
				logger.info("\n")
				logger.info(json_input_for_controller_service)
				logger.info("\n")
				logger.info(client_id)
				logger.info("\n")
				logger.info(nifi_server_ip)
				r = create_controller_service(nifi_server_ip, json_input_for_controller_service, client_id,
											  header_with_auth_taoken)
				logger.info('Response from the Nifi server to create controller service')
				logger.info(r)
				rj = json.loads(r)
				c_id = rj['id']
				print c_id
				controllerServiceguid.append(c_id + ':' + controller_service_name + '\n')
				logger.info('Enabling Controller service')
				update_processorinput = update_state_input_json_for_controller_service(c_id)
				update_response = update_controller_service(nifi_server_ip, update_processorinput, c_id,
															header_with_auth_taoken)
				logger.info(update_response)
				print update_response
			#send_ask(''.join(controllerServiceguid), 'onkar.pathak@libertymutual.com')

		# uploading xml template in nifi server
		parent_processor_guid = ''
		if configParser.get('nifi-action', 'action') == 'upload template and update':
			xml_res = upload_template_to_nifiserver(nifi_server_ip, files, header_with_auth_taoken, client_id)
			try:
				# temaplte id extraction from json file
				#xml_res = upload_template_to_nifiserver(nifi_server_ip, files, header_with_auth_taoken, client_id)
				root = ET.fromstring(xml_res)
				print root.tag
				logger.info(root.tag)
				print root[0][2].text
				logger.info(root[0][2].text)
				uploaded_template_id = root[0][2].text
				print("NiFi Token generated from user for user:"+nifi_username+"  and password: "+nifi_password+" is as: "+token)
				logger.info("Uploaded Template ID is : "+uploaded_template_id)
				logger.info("Template Uploadation Status if success then guid should come")
				logger.info(uploaded_template_id)
			except Exception as e:
				print e
				logger.info("Template Uploadation Status if sucess then guid should come")
				logger.info(xml_res)
				send_ack('Sending Loge File to email Address.','onkar.pathak@libertymutual.com')
			# adding nifi template to the nifi canvas
			intiate_temaplte_json = json_input_to_intisate_templat(uploaded_template_id)
			logger.info(intiate_temaplte_json)
			res_intiate_template = intiate_temaplate(nifi_server_ip, intiate_temaplte_json, header_with_auth_taoken,
													 client_id)
			print res_intiate_template
			logger.info("Template intiation status in nifi canvas")
			logger.info(res_intiate_template)
			print res_intiate_template['flow']['processGroups'][0]['status']['aggregateSnapshot']['id']
			print res_intiate_template['flow']['processGroups'][0]['status']['aggregateSnapshot']['name']
			parent_processor_guid = res_intiate_template['flow']['processGroups'][0]['status']['aggregateSnapshot']['id']
			print parent_processor_guid
			logger.info("Parent processor GUID from if block is: "+parent_processor_guid)

			send_ack('Upload template and update complted.','onkar.pathak@libertymutual.com')
		else:
			parent_processor_guid = client_id



		# creating data frame of processors/processorsgroup and guid from server
		pr_group1 = procrssor_group_id(nifi_server_ip, parent_processor_guid, header_with_auth_taoken)
		search_resursive(pr_group1, nifi_server_ip, header_with_auth_taoken)
		logger.info("Parent processor GUID outside if else is: "+parent_processor_guid)

		dataframe_with_name_guid = pd.DataFrame({'ProcessorGroupName': processor_names, 'GUID': processor_ids})
		print dataframe_with_name_guid
		logger.info('Dataframe with processor name & GUID')
		logger.info(dataframe_with_name_guid)

		logger.info('Dataframe indexing is under progress')
		# Indexing daatframe based on procesor name
		processor_name = dataframe_with_name_guid['ProcessorGroupName']
		dataframe_with_name_guid = dataframe_with_name_guid.set_index(processor_name)
		logger.info('Dataframe indexing done')

		logger.info('Reading configuration file to update processor')
		# reading nifi processor config file to update processor
		env_name = aws_env_name().lower()
		if env_name=='integration':
			env_name = 'integration'
		else:
			env_name = 'prod'
		config_data = reading_config_file('/code/data_ingest/' + data_source_name +'_'+env_name+'_config.txt')
		# config_data = reading_config_file('C:\\Users\\n0304026\\Desktop\\nifi_CodeDeploy\\template_icd_config.txt')
		config_data = config_data.fillna('')
		logger.info('Reading configuration file done.')
		for (index, keyvalues) in config_data.iterrows():
			print keyvalues['name']
			logger.info('Processor Name to update')
			logger.info(keyvalues['name'])
			# searching processor guid based on processor name
			try:
				guid_of_processor = search_processor_guid_based_on_processor_name(keyvalues['name'], dataframe_with_name_guid)
				logger.info('Processor GUID to update')
				logger.info(guid_of_processor)
				print guid_of_processor
				#print update_input_json_for_processor(keyvalues, guid_of_processor)
				# creating json file for  nifi processors based on config file
				if guid_of_processor!='Not Found':
					json_to_update = update_input_json_for_processor(keyvalues, guid_of_processor)
					logger.info('Input Json to update processor')
					logger.info(json_to_update)
					# updating processors
					if json_to_update!='Update Failed':
						update_processor_res = update_processor(nifi_server_ip, json.loads(json_to_update), guid_of_processor,
													header_with_auth_taoken)
						logger.info('Response from server after updating processor')
						logger.info(update_processor_res)
			except:
				logger.info("error while updating processor/processor group with name : "+keyvalues['name']+" Continue...")

		send_ack('Sending Log File to email Address.','onkar.pathak@libertymutual.com')
	except:
		send_ack('Sending Log File to email Address from Main except.','onkar.pathak@libertymutual.com')


if __name__ == '__main__':
    #send_ack('Sending Loge File to email Address.','onkar.pathak@libertymutual.com')
    sys.exit(main())
