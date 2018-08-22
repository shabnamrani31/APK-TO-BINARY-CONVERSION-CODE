from androguard.core.bytecodes import dvm, apk
import glob
import binascii
import os
#from utils import *
from python_utils import *
apks_dir = "C:/Users/Shabnam Rani/Desktop/dataset"
# apks_dir = '../apks/virusshare'

output_dir = "C:/Users/Shabnam Rani/Desktop/50 malicious"
sequence_postfix = ".txt"




from multiprocessing.dummy import Pool as ThreadPool
pool = ThreadPool(20)

def convert_apk(fname):
    try:
        print('Start function')    
        a = apk.APK(fname)
        j = dvm.DalvikVMFormat(a.get_dex())
        print('\n End function \n ') 
        print('value of A is \n ',a)
        print('\n \n value of J is \n ',j)
        file_basename = os.path.basename(fname)
        out_filename = output_dir + "/" + file_basename + sequence_postfix

        instructions_count = 0
        with open(out_filename, "w") as out_f:
            for method in j.get_methods():
                print('\n method value',method)   
                
                code = method.get_code()
                if code != None:
                    bc = code.get_bc()
                    print('Check \n ',bc)
                    for i in bc.get_instructions():
                        
                        print('\n value of bc is ',type(i))
                       #hex1 = hex(   i.get_raw()     )+"\n"
                        #hex1=binascii.b2a_uu(i.get_raw())
                        hex1 = binascii.hexlify( i.get_raw() )
                        #binary=bin(hex1)
                        hex2=str(hex1,'ascii')
                        #binary_string = binascii.unhexlify(hex2)
                        scale = 16 ## equals to hexadecimal
                        num_of_bits = 16
                       
                        hex3=bin(int(hex2, scale)%255)[2:].zfill(num_of_bits)
                     
                        print("\n type of hex 3 is \n ",len(hex3),"\n ",hex3)
#                        #hex3=str(binary_string)
#                        for i in range(0,256) :
#                            print('Check hello \n ')
#                        if (len(hex3) < 16):
#                                #s='0'
#                                print('Check bbbbbb\n ')
#                                c=16-len(hex3)
#                                print('c kivalue',c)
##                                for i in range(0,c) :
###                                print('Check hello \n ')
####                                
##                                    ##                                i=i+1
#                                hex3=hex3.zfill(16)
#                                print('string bari kerdi ',hex3)
                        
        
                        out_f.write(hex3[:16:]+"\n")
                        instructions_count += 1
                        
                else:
                    pass
                    # print("- No code found.") # too many of these
        return instructions_count
        # max_sequence_size = max(max_sequence_size, instructions_count)
    except Exception as e:
        print("Error handling file: %s " % fname)
        print(e) # and then continue

def convert_to_sequences(apks_dir, output_dir, sequence_postfix):
    apk_files = glob.glob(apks_dir + "/*")
    total_files = len(apk_files)

    results = pool.map(convert_apk, apk_files)
    print('Value of result variable is \n \n ',results)
    #max_sequence_size = max(results)

    # for i, fname in enumerate(apk_files):
        # print("Processing %5d/%5d" %(i+1, total_files))


    # print("Max sequence size seen: %d" % max_sequence_size)

if __name__ == '__main__':
    convert_to_sequences(apks_dir, output_dir, sequence_postfix)