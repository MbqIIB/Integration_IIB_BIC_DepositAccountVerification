import java.io.FileInputStream;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.security.Key;

import javax.crypto.Cipher;

import com.ibm.broker.config.proxy.*;
import com.ibm.broker.javacompute.MbJavaComputeNode;
import com.ibm.broker.plugin.*;

public class PWRetreiver_EPOBSWSSA extends MbJavaComputeNode {

//**************************************************************
	private final static String TEST_PW_STASH_PATH = "//var//mqsi//components//MBY1//keystores//PWStash//";
	private final static String PROD_PW_STASH_PATH = "//var//mqsi//components//MBZ1//prod//keystores//PWStash//";
	private final static String KEY_IDENTIFIER = "KEY";
	private final static String PW_STASH_FILE_EXTENSION = ".aes";
	private String pw_STASH_PATH;
	private String brkrName;
	private String egName;
	private BrokerProxy b;
	private ExecutionGroupProxy e;
	private MessageFlowProxy m;
	private String attribute;


//**************************************************************	

	public void evaluate(MbMessageAssembly assembly) throws MbException {
		MbOutputTerminal out = getOutputTerminal("out");
//		MbOutputTerminal alt = getOutputTerminal("alternate");

//		MbMessage message = assembly.getMessage();

// Add user code below
// ****************************************************
		
		try{
			egName = getExecutionGroup().getName();
			b = BrokerProxy.getLocalInstance();
			e  = b.getExecutionGroupByName(egName);
			
// This section is ugly and should be fixed maybe a CASE statement
// AnderaPrescreen
			m = e.getMessageFlowByName("com.tcfbank.www.AnderaPrescreen");
			attribute = (String) m.getUserDefinedProperty("MB_user");
			if (attribute.equalsIgnoreCase("empty")){
						PWRetriever("MB_user");
			}
		}catch(Exception er1){
			er1.printStackTrace();
		}
//******************************************************
// End of user code

		// The following should only be changed
		// if not propagating message to the 'out' terminal

		out.propagate(assembly);
	}
//**************************************************************************
	public void PWRetriever(String userAttribute) throws Exception{

// Set the stash path for prod or test right now there is no development default but this should default to a development stash path.			
		brkrName = getBroker().getName();
		if(brkrName.equals("MBZ1")){
			pw_STASH_PATH = PROD_PW_STASH_PATH;			
		}else if(brkrName.equals("MBY1")){
			pw_STASH_PATH = TEST_PW_STASH_PATH;
		}
		
        ObjectInputStream keyIn = new ObjectInputStream(new FileInputStream(pw_STASH_PATH + userAttribute + KEY_IDENTIFIER + PW_STASH_FILE_EXTENSION));
        Key key = (Key) keyIn.readObject();
        keyIn.close();

        InputStream in = new FileInputStream(pw_STASH_PATH + userAttribute + PW_STASH_FILE_EXTENSION);
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

