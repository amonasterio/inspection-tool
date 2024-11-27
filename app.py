# Credit @tobias_willmann
from google.oauth2 import service_account
from googleapiclient.discovery import build
from oauth2client import client
from oauth2client import file
from oauth2client import tools
import argparse
import httplib2
import pandas as pd
from datetime import datetime
import re


def getCurrentDate():
  return datetime.now()

def getNombreFichero(url_propiedad):
  if url_propiedad.startswith('sc-domain:'):
        dominio=url_propiedad.replace('sc-domain:','')
  else:
      m = re.search('https?://([A-Za-z_0-9.-]+).*',url_propiedad)
      dominio=m.group(1)
  formato_salida='%Y%m%d-%H%M%S'
  now = getCurrentDate()
  nombre_fichero='output/'+now.strftime(formato_salida)+"_"+dominio+".csv"
  return nombre_fichero

cuenta='eventflare'
authorized='authorizedcreds_'+cuenta+'.dat' #guardará credenciales cuando nos hayamos logado
propiedad='https://eventflare.io/'
key='../credentials/client_secrets_'+cuenta+'.json'
f_entrada='url-list.csv'
f_salida=getNombreFichero(propiedad)





def authorize_creds(creds,authorizedcreds=authorized):
    '''
    Authorize credentials using OAuth2.
    '''
    print('Authorizing Creds')
    # Variable parameter that controls the set of resources that the access token permits.
    SCOPES = ['https://www.googleapis.com/auth/webmasters.readonly'] 
 
    # Path to client_secrets.json file
    CLIENT_SECRETS_PATH = creds
 
    # Create a parser to be able to open browser for Authorization
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        parents=[tools.argparser])
    flags = parser.parse_args([])
 
    # Creates an authorization flow from a clientsecrets file.
    # Will raise InvalidClientSecretsError for unknown types of Flows.
    flow = client.flow_from_clientsecrets(
        CLIENT_SECRETS_PATH, scope = SCOPES,
        message = tools.message_if_missing(CLIENT_SECRETS_PATH))
 
    # Prepare credentials and authorize HTTP
    # If they exist, get them from the storage object
    # credentials will get written back to the 'authorizedcreds.dat' file.
    storage = file.Storage(authorizedcreds)
    credentials = storage.get()
 
    # If authenticated credentials don't exist, open Browser to authenticate
    if credentials is None or credentials.invalid:
        credentials = tools.run_flow(flow, storage, flags)      # Add the valid creds to a variable
 
    # Take the credentials and authorize them using httplib2   
    http = httplib2.Http()                                      # Creates an HTTP client object to make the http request
    http = credentials.authorize(http=http)                     # Sign each request from the HTTP client with the OAuth 2.0 access token
    webmasters_service = build('searchconsole', 'v1', http=http)   # Construct a Resource to interact with the API using the Authorized HTTP Client.
 
    print('Auth Successful')
    return webmasters_service

def getResultado(service,site_url,propiedad):
  request = {
        'inspectionUrl': site_url,
        'siteUrl': propiedad
  }
  try:
    dict={}
    response = service.urlInspection().index().inspect(body=request).execute()
    if response is not None:
      if response.get('inspectionResult')!=None:
        inspectionResult = response['inspectionResult']      
        if inspectionResult['indexStatusResult']!=None:
          dict['url']=site_url
          dict['currentDate']=getCurrentDate()
          if inspectionResult['indexStatusResult'].get('verdict')!=None:
            dict['verdict']=inspectionResult['indexStatusResult']['verdict']
          if inspectionResult['indexStatusResult'].get('coverageState')!=None:
            dict['coverageState']=inspectionResult['indexStatusResult']['coverageState']
          if inspectionResult['indexStatusResult'].get('robotsTxtState')!=None:
            dict['robotsTxtState']=inspectionResult['indexStatusResult']['robotsTxtState']
          if inspectionResult['indexStatusResult'].get('indexingState')!=None:
            dict['indexingState']=inspectionResult['indexStatusResult']['indexingState']
          if inspectionResult['indexStatusResult'].get('lastCrawlTime')!=None:
            dict['lastCrawlTime']=inspectionResult['indexStatusResult']['lastCrawlTime']
          if inspectionResult['indexStatusResult'].get('pageFetchState')!=None:
            dict['pageFetchState']=inspectionResult['indexStatusResult']['pageFetchState']
          if inspectionResult['indexStatusResult'].get('googleCanonical')!=None:
            dict['googleCanonical']=inspectionResult['indexStatusResult']['googleCanonical']
          if inspectionResult['indexStatusResult'].get('userCanonical')!=None:
            dict['userCanonical']=inspectionResult['indexStatusResult']['userCanonical']
          if inspectionResult['indexStatusResult'].get('referringUrls')!=None:
            l_refererring=inspectionResult['indexStatusResult']['referringUrls']
            if len(l_refererring)>0:
               dict["referreferringUrls"]=l_refererring
          if inspectionResult['indexStatusResult'].get('sitemap')!=None:
            l_sitemap=inspectionResult['indexStatusResult']['sitemap']
            if len(l_sitemap)>0:
               dict["sitemap"]=l_sitemap
          if inspectionResult['indexStatusResult'].get('referringUrls')!=None:
            l_refererring=inspectionResult['indexStatusResult']['referringUrls']
            if len(l_refererring)>0:
               dict["referreferringUrls"]=l_refererring
          dict['error']=''
  except KeyError as e:
      dict['url']=site_url
      dict['currentDate']=getCurrentDate()
      if e is not None:
        print('Error al recuperar parámetro '+ e.args[0]+' en '+site_url)
        dict['error']=e.args[0]
      else:
        dict['error']='Error al recuperar un campo'
  except httplib2.ServerNotFoundError as e:
      print ("Site is Down")
      dict['url']=site_url
      dict['currentDate']=getCurrentDate()
      if e is not None:
        dict['error']=e.args[0]
      else:
        dict['error']='Error del servidor'
  except Exception as e:
      print ("Error desconocido")
      dict['url']=site_url
      dict['currentDate']=getCurrentDate()
      if e is not None:
        dict['error']=e.args[0]
      else:
        dict['error']='Error desconocido'
  return dict

if __name__ == '__main__':
    creds = key
    service = authorize_creds(creds) 
    df_entrada=pd.read_csv(f_entrada,header=None)
    df_salida=pd.DataFrame([],index=None)
    lista=df_entrada[0].values.tolist()
    results=[]
    i=0
    for element in lista:
      res=getResultado(service,element,propiedad)
      i+=1
      print(i)
      print(res)
      results.append(res)
    df_salida=pd.DataFrame.from_dict(results)
    df_salida.to_csv(f_salida, index=False,decimal='.', sep=',',quotechar='"')   