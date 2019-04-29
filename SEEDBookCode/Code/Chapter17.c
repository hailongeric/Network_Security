
/******************************
 * Code in Chapter 17
 ******************************/


/**********************************************
 * Code on Page 338 (Section 17.1)
 **********************************************/

unsigned int payload;
unsigned int padding = 16; 

// Read from the type field.
hbtype = *p++;  

// Reads 16 bits from the payload field, and and store the value 
//   in the variable payload. 
n2s(p, payload);                                      
			  
pl=p; // pl now points to the beginning of the payload content.
			  
if (hbtype == TLS1_HB_REQUEST)
{
  unsigned char *buffer, *bp;
  int r;

  // Allocate memory for the response packet: 
  // 1 byte for message type, 2 bytes for payload length, 
  // plus payload size, and padding size.
  buffer = OPENSSL_malloc(1 + 2 + payload + padding);    
  bp = buffer;

  // Set the response type and the payload length fields.
  *bp++ = TLS1_HB_RESPONSE;
  s2n(payload, bp);
        
  // Copy the data from the request packet to the response packet; 
  // pl points to the payload region in the request packet.  
  memcpy(bp, pl, payload);                              
  bp += payload;

  // Add paddings.
  RAND_pseudo_bytes(bp, padding);			    

  // Code omitted: send out the response packet.
  ......
}



/**********************************************
 * Code on Page 341 (Section 17.2.2)
 **********************************************/

 def build_heartbeat(tls_ver):

 heartbeat = [
    # TLS record header
    0x18,           # Content Type (0x18 means Heartbeat)
    0x03, tls_ver,  # TLS version
    0x00, 0x29,     # Length

    # Heartbeat packet header
    0x01,           # Hearbet packet Type (0x01 means Request)
    0x00, 0x16,     # Declared payload length
    #-------------------------------------------------------
    0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
    0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
    0x41, 0x41, 0x41, 0x41, 0x41, 0x42, 
    # Payload content ends 22 bytes
    #-------------------------------------------------------
    0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C,
    0x4D, 0x4E, 0x4F, 0x41, 0x42, 0x43, 0x44, 0x45
    # Paddings ends 16 bytes
    #-------------------------------------------------------
 ] 
 return heartbeat


