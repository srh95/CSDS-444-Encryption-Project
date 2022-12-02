def utf8len(s):
    return len(s.encode('utf-8'))

if __name__ == '__main__':
   s = "CRYPTOGRAPHYBEGANWITHCIPHERS,THEFIRSTOFWHICHWASTHECAESARCIPHER."
   s2 = "CRYPTOGRAPHYBEGANWITHCIPHERS,THEFIRSTOFWHICHWASTHECAESARCIPHER.CIPHERSWEREALOTEASIERTOUNRAVELCOMPAREDTOMODERNCRYPTOGRAPHICALGORITHMS,BUTTHEYBOTHUSEDKEYSANDPLAINTEXT.THOUGHSIMPLE,CIPHERSFROMTHEPASTWERETHEEARLIESTFORMSOFENCRYPTION."
   s3 = "CRYPTOGRAPHYBEGANWITHCIPHERS,THEFIRSTOFWHICHWASTHECAESARCIPHER. CIPHERSWEREALOTEASIERTOUNRAVELCOMPAREDTOMODERNCRYPTOGRAPHICALGORITHMS,BUTTHEYBOTHUSEDKEYSANDPLAINTEXT.THOUGHSIMPLE,CIPHERSFROMTHEPAST WERETHEEARLIESTFORMSOFENCRYPTION.TODAYSALGORITHMSANDCRYPTOSYSTEMSAREMUCHMOREADVANCED.THEYUSEMULTIPLEROUNDSOFCIPHERSANDENCRYPTINGTHE CIPHERTEXTOFMESSAGESTOENSURETHEMOSTSECURETRANSITANDSTORAGEOFDATA."
   res = len(s2.encode('utf-8'))

   # print result
   print("The length of string in bytes : " + str(res))


