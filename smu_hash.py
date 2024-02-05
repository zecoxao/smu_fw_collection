from Crypto.Hash import SHA1, HMAC
from binascii import unhexlify as uhx
from binascii import hexlify as hx
import os
import struct
import sys

'''

/// Firmware header
typedef struct {
  UINT32  Digest[5];                ///< Digest
  UINT32  Version;                  ///< Version
  UINT32  HeaderSize;               ///< Header length
  UINT32  Flags;                    ///< Flags
  UINT32  EntryPoint;               ///< Entry Point
  UINT32  CodeSize;                 ///< Code Size
  UINT32  ImageSize;                ///< Image Size
  UINT32  Rtos;                     ///< Rtos
  UINT32  SoftRegisters;            ///< Soft Registers
  UINT32  DpmTable;                 ///< Dpm Table
  UINT32  FanTable;                 ///< Fan Table
  UINT32  CacConfigTable;           ///< Cac Configuration Table
  UINT32  CacStatusTable;           ///< Cac Status Table
  UINT32  mcRegisterTable;          ///< mc Register Table
  UINT32  mcArbDramTimingTable;     ///< mc Arb Dram Timing Table
  UINT32  Globals;                  ///< Globals
  UINT32  Signature;                ///< Signature
  UINT32  Reserved[44];             ///< Reserved space 
} FIRMWARE_HEADER_V7;

^^^ WTF this is size 0x104...

'''

class SMU:
	
	def __init__(self, f):
		
		f.seek(0x0)
		
		# SMU Firmware Family Header
		self.FFH_MAGIC                = struct.unpack('8s',  f.read(8))[0]
		self.FFH_FWSIZE               = struct.unpack('>I',  f.read(4))[0]
		self.FFH_UNK                  = struct.unpack('>I',  f.read(4))[0]
		self.FFH_ENTRY                = struct.unpack('>I',  f.read(4))[0]
		self.FFH_UNK2                 = struct.unpack('>I',  f.read(4))[0]
		self.FFH_CODENAME             = struct.unpack('2s',  f.read(2))[0]
		self.FFH_PADDING              = struct.unpack('22s', f.read(22))[0]
		
		print('')
		print('SMU Firmware Header Family:')
		print('')
		print('  Magic:                     %s'   % self.FFH_MAGIC.decode())
		print('  Firmware Size:             0x%X' % self.FFH_FWSIZE)
		print('  Unknown:                   0x%X' % self.FFH_UNK)
		print('  Entry:                     0x%X' % self.FFH_ENTRY)
		print('  Unknown2:                  0x%X' % self.FFH_UNK2)
		print('  Codename:                  %s'   % self.FFH_CODENAME.decode())
		
		# SMU Header V7
		self.DIGEST                   = struct.unpack('20s',  f.read(20))[0]
		
		# SMU Body
		self.VERSION                  = struct.unpack('>I',   f.read(4))[0]
		self.HEADER_SIZE              = struct.unpack('>I',   f.read(4))[0]
		self.FLAGS                    = struct.unpack('>I',   f.read(4))[0]
		self.ENTRY_POINT              = struct.unpack('>I',   f.read(4))[0]
		self.CODE_SIZE                = struct.unpack('>I',   f.read(4))[0]
		self.IMAGE_SIZE               = struct.unpack('>I',   f.read(4))[0]
		self.RTOS                     = struct.unpack('>I',   f.read(4))[0]
		self.SOFT_REGISTERS           = struct.unpack('>I',   f.read(4))[0]
		self.DPM_TABLE                = struct.unpack('>I',   f.read(4))[0]
		self.FAN_TABLE                = struct.unpack('>I',   f.read(4))[0]
		self.CAC_CONFIG_TABLE         = struct.unpack('>I',   f.read(4))[0]
		self.CAC_STATUS_TABLE         = struct.unpack('>I',   f.read(4))[0]
		self.MC_REGISTER_TABLE        = struct.unpack('>I',   f.read(4))[0]
		self.MC_ARB_DRAM_TIMING_TABLE = struct.unpack('>I',   f.read(4))[0]
		self.GLOBALS                  = struct.unpack('>I',   f.read(4))[0]
		self.SIGNATURE                = struct.unpack('>I',   f.read(4))[0]
		self.RESERVED                 = struct.unpack('>43I', f.read(172))[0]
		
		print('')
		print('SMU Firmware Header V7:')
		print('')
		print('  Digest:                    0x%s' % hx(self.DIGEST).upper().decode())
		print('  Version:                   0x%X' % self.VERSION)
		print('  Header Size:               0x%X' % self.HEADER_SIZE)
		print('  Flags:                     0x%X' % self.FLAGS)
		print('  Entry Point:               0x%X' % self.ENTRY_POINT)
		print('  Code Size:                 0x%X' % self.CODE_SIZE)
		print('  Image Size:                0x%X' % self.IMAGE_SIZE)
		print('  Rtos:                      0x%X' % self.RTOS)
		print('  Soft Registers:            0x%X' % self.SOFT_REGISTERS)
		print('  Dpm Table:                 0x%X' % self.DPM_TABLE)
		print('  Fan Table:                 0x%X' % self.FAN_TABLE)
		print('  Cac Configuration Table:   0x%X' % self.CAC_CONFIG_TABLE)
		print('  Cac Status Table:          0x%X' % self.CAC_STATUS_TABLE)
		print('  mc Register Table:         0x%X' % self.MC_REGISTER_TABLE)
		print('  mc Arb Dram Timing Table:  0x%X' % self.MC_ARB_DRAM_TIMING_TABLE)
		print('  Globals:                   0x%X' % self.GLOBALS)
		print('  Signature:                 0x%X' % self.SIGNATURE)
		
		f.seek(0x44)
		self.IMAGE = f.read()
	

try:
	if sys.argv[1].upper() == 'J':
		isPS4 = True
	else:
		isPS4 = False
except:
	isPS4 = False

# PS4 - 1.01
if isPS4:
	guess = b'4D7E73210B677A832B9F293B496E7C3E'
	smufw = 'jaguar_ps4_smu_firmware_be.bin'

# SMU Firmware Image From Flash Dump
with open(sys.argv[1], 'rb') as INPUT:
	smu = SMU(INPUT)

'''

# PS4 - 1.01

	4D7E73210B677A832B9F293B496E7C3E
	B92864EBE65FE8C51B916908477E5FB63AD5B9ED

'''

print()
hmac = HMAC.new(uhx('4D7E73210B677A832B9F293B496E7C3E'), smu.IMAGE, SHA1).hexdigest().upper()

if hmac == hx(smu.DIGEST).upper().decode():
	result = 'PASS'
else:
	result = 'FAIL'

print('Digest Check:  %s          0x%s' % (result, hmac))
