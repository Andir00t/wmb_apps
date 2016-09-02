package ru.pochtabank.esb.httpclient;

import java.io.UnsupportedEncodingException;

import com.ibm.broker.javacompute.MbJavaComputeNode;
import com.ibm.broker.plugin.MbElement;
import com.ibm.broker.plugin.MbException;
import com.ibm.broker.plugin.MbMessage;
import com.ibm.broker.plugin.MbMessageAssembly;
import com.ibm.broker.plugin.MbOutputTerminal;
import com.ibm.broker.plugin.MbUserException;
import com.ibm.broker.plugin.MbXMLNS;
import com.ibm.broker.plugin.MbXMLNSC;


import org.apache.commons.httpclient.Credentials;
import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.UsernamePasswordCredentials;
import org.apache.commons.httpclient.auth.AuthScope;
import org.apache.commons.httpclient.methods.PostMethod;
import org.apache.commons.httpclient.methods.StringRequestEntity;


public class EFRSB_HTTP_Client extends MbJavaComputeNode {
		
		String login = (String)getUserDefinedAttribute("Login");
		String pass = (String)getUserDefinedAttribute("Password");
		String url = (String)getUserDefinedAttribute("URL");
		int timeout = (int)getUserDefinedAttribute("Timeout");
		String proxy = (String)getUserDefinedAttribute("Proxy");
		String soapaction = (String)getUserDefinedAttribute("Operation");
		String proxy_host = proxy.split(":")[0];
		String proxy_port = proxy.split(":")[1];
		

		public void evaluate(MbMessageAssembly inAssembly) throws MbException {
			MbOutputTerminal out = getOutputTerminal("out");
			MbOutputTerminal error = getOutputTerminal("alternate");
			MbMessage inMessage = inAssembly.getMessage();
			MbMessage outMessage = new MbMessage(); 
			MbMessageAssembly outAssembly = new MbMessageAssembly(inAssembly, outMessage);
			String response = "";
			String statusCode;
			
			
			try {
				
				  MbElement root = inMessage.getRootElement();
				  MbElement SoapBody = root.getLastChild();
	              byte[] b = SoapBody.toBitstream("", "", "", 0, 0, 0);
				  String SoapBodyValue  = new String(b);
				  String SoapAction = "http://tempuri.org/IMessageService/" + soapaction;
				  String result = getBankruptWS(SoapBodyValue, SoapAction);
				  statusCode = result.split("#-#")[0];
				  response = result.split("#-#")[1];
				  outMessage.getRootElement().createElementAsLastChildFromBitstream( response.getBytes("UTF-8"), MbXMLNSC.PARSER_NAME, null, null, null, 546, 1208, 0); 
			 
				  
				
			} catch (MbException e) {
				throw e;
			} catch (RuntimeException e) {
				throw e;
			} catch (Exception e) {
				throw new MbUserException(this, "evaluate()", "", "", e.toString(),
						null);
			}
			
			if (!statusCode.isEmpty() && statusCode.equals("OK"))
			{ out.propagate(outAssembly); }
			else 
			{ error.propagate(outAssembly);}
			
		}	

		public String getBankruptWS (String xmlStr, String soapAction) throws MbException, UnsupportedEncodingException  {
	    	
			String data = "<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:tem=\"http://tempuri.org/\">"
		    			+ "<soapenv:Header/>"
		    			+ "<soapenv:Body>"
		    			+ xmlStr
		    			+ "</soapenv:Body>" 
		    			+ "</soapenv:Envelope>";
		 		    
		    	System.setProperty("org.apache.commons.logging.Log", "org.apache.commons.logging.impl.NoOpLog");
			    PostMethod post = new PostMethod(url);
			    StringRequestEntity req = new StringRequestEntity(data, "text/xml", "UTF-8");
			    post.setRequestHeader("SOAPAction", soapAction);
			    post.setRequestEntity(req);
		        HttpClient httpclient = new HttpClient();
		        Credentials defaultcreds = new UsernamePasswordCredentials(login, pass);
		        httpclient.getState().setCredentials(AuthScope.ANY, defaultcreds);
		        httpclient.getHttpConnectionManager().getParams().setSoTimeout(timeout);
		       // httpclient.getHostConfiguration().setProxy(proxy_host, Integer.parseInt(proxy_port));
		         
		        try {
		        	
		        	httpclient.executeMethod(post);
		        	return post.getStatusText() + "#-#" + post.getResponseBodyAsString();
		         
		        
				}
			    	catch (Exception ex){
			           MbUserException mbue = new MbUserException(this, "evaluate()", "", "", ex.toString(), null);
			    	    throw mbue;
			    	 			    }
		       finally {
		            
		            post.releaseConnection();
		        }  
		     
		}
	}
