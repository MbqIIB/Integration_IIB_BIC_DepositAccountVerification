package com.tcfbank.www;

import java.io.FileInputStream;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.security.Key;

import javax.crypto.Cipher;

import com.ibm.broker.config.proxy.*;
import com.ibm.broker.javacompute.MbJavaComputeNode;
import com.ibm.broker.plugin.*;

public class TellerAccountVerification_PWRetreiver extends MbJavaComputeNode {

	//**************************************************************
	private final static String PW_STASH_PATH = "D:\\MBKeystore\\PWStash\\";
	private final static String KEY_IDENTIFIER = "KEY";
	private final static String PW_STASH_FILE_EXTENSION = ".aes";

//**************************************************************	

	public void evaluate(MbMessageAssembly assembly) throws MbException {
		MbOutputTerminal out = getOutputTerminal("out");
//		MbOutputTerminal alt = getOutputTerminal("alternate");

//		MbMessage message = assembly.getMessage();

// Add user code below
// ****************************************************
		String TestingToolAttribute = (String)getUserDefinedAttribute("TestingTool");
		if (TestingToolAttribute.length() == 0){
				try {
					PWRetriever("TestingTool");
				} catch (Exception e2) {
					e2.printStackTrace();
				}
		}
		String TLR_userAttribute = (String)getUserDefinedAttribute("TLR_user");
		if (TLR_userAttribute.length() == 0){
				try {
					PWRetriever("TLR_user");
				} catch (Exception e2) {
					e2.printStackTrace();
				}
		}
		String BIC_userAttribute = (String)getUserDefinedAttribute("BIC_user");
		if (BIC_userAttribute.length() == 0){
				try {
					PWRetriever("BIC_user");
				} catch (Exception e2) {
					e2.printStackTrace();
				}
		}

//******************************************************
// End of user code

		// The following should only be changed
		// if not propagating message to the 'out' terminal

		out.propagate(assembly);
	}
//**************************************************************************
	public void PWRetriever(String userAttribute) throws Exception{
		
		String egName = getExecutionGroup().getName();
		BrokerProxy b = BrokerProxy.getLocalInstance();
		ExecutionGroupProxy e = b.getExecutionGroupByName(egName);
		String flowName = getMessageFlow().getName();
		MessageFlowProxy m = e.getMessageFlowByName(flowName);

        ObjectInputStream keyIn = new ObjectInputStream(new FileInputStream(PW_STASH_PATH + userAttribute + KEY_IDENTIFIER + PW_STASH_FILE_EXTENSION));
        Key key = (Key) keyIn.readObject();
        keyIn.close();

        InputStream in = new FileInputStream(PW_STASH_PATH + userAttribute + PW_STASH_FILE_EXTENSION);
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, key);

		int blockSize = cipher.getBlockSize();
	    int outputSize = cipher.getOutputSize(blockSize);
	    byte[] inBytes = new byte[blockSize];
	    byte[] outBytes = new byte[outputSize];
	    
	    int inLength = 0;
	    StringBuffer pwBuffer = new StringBuffer();
	    boolean more = true;
	    while (more)
	    {
	       inLength = in.read(inBytes);
	       if (inLength == blockSize)
	       {
	          int outLength = cipher.update(inBytes, 0, blockSize, outBytes);
	          if(outLength > 0){
	        	  String str = new String(outBytes);
	        	  pwBuffer.append(str);
	          }
	       }
	       else more = false;
	    }
	    if (inLength > 0) outBytes = cipher.doFinal(inBytes, 0, inLength);
	    else outBytes = cipher.doFinal();
	    String s = new String(outBytes);
	    pwBuffer.append(s);
	    m.setUserDefinedProperty(userAttribute, pwBuffer.toString());
	    in.close();
	}
//***************************************************************
}
