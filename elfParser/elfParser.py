
# -*- coding: utf-8 -*-

from locale import atoi
import sys
import mmap
import struct


DYNAMIC_TYPE = {
    0: 'NULL',
    1: 'NEEDED',
    2: 'PLTRELSZ',
    3: 'PLTGOT',
    4: 'HASH',
    5: 'STRTAB',
    6: 'SYMTAB',
    7: 'RELA',
    8: 'RELASZ',
    9: 'RELAENT',
    10: 'STRSZ',
    11: 'SYMENT',
    12: 'INIT',
    13: 'FINIT',
    14: 'SONAME',
    15: 'RPATH',
    16: 'SYMBOLIC',
    17: 'REL',
    18: 'RELSZ',
    19: 'RELENT',
    20: 'PLTREL',
    21: 'DEBUG',
    22: 'TEXTREL',
    23: 'JMPREL',
    26: 'FINIT_ARRAY',
    28: 'FINIT_ARRAYSZ',
    25: 'INIT_ARRAY',
    27: 'INIT_ARRAYSZ',
    30: 'FLAGS',
    32: 'PREINIT_ARRAY',
    33: 'PREINIT_ARRAYSZ',
    0x6FFFFFFA: 'RELCOUNT',
    0x6FFFFFFB: 'FLAGS_1',
    0x6ffffff0: 'VERSYM',
    0x6ffffffe: 'VERNEED',
    0x6fffffff: 'VERNEEDNUM',
    0x70000000: 'LOPROC',
    0x7fffffff: 'HIPROC',
    0x70000001: 'MIPS_RLD_VERSION',
    0x70000002: 'MIPS_TIME_STAMP',
    0x70000003: 'MIPS_ICHECKSUM',
    0x70000004: 'MIPS_IVERSION',
    0x70000005: 'MIPS_FLAGS',
    0x70000006: 'MIPS_BASE_ADDRESS',
    0x70000008: 'MIPS_CONFLICT',
    0x70000009: 'MIPS_LIBLIST',
    0x7000000a: 'MIPS_LOCAL_GOTNO',
    0x7000000b: 'MIPS_CONFLICTNO',
    0x70000010: 'MIPS_LIBLISTNO',
    0x70000011: 'MIPS_SYMTABNO',
    0x70000012: 'MIPS_UNREFEXTNO',
    0x70000013: 'MIPS_GOTSYM',
    0x70000014: 'MIPS_HIPAGENO',
    0x70000016: 'MIPS_RLD_MAP',
    0x6ffffef5: 'GNU_HASH',

}

SH_TYPE_MAP_LIST = {'0x0':'SHT_NULL',
                    '0x1':'SHT_PROGBITS',
                    '0x2':'SHT_SYMTAB',
                    '0x3':'SHT_STRTAB',
                    '0x4':'SHT_RELA',
                    '0x5':'SHT_HASH',
                    '0x6':'SHT_DYNAMIC',
                    '0x7':'SHT_NOTE',
                    '0x8':'SHT_NOBITS',
                    '0x9':'SHT_REL',
                    '0xa':'SHT_SHLIB',
                    '0xb':'SHT_DYNSYM',
                    '0xc':'SHT_NUM',
                    '0xe':'SHT_INIT_ARRAY',
                    '0xf':'SHT_FINI_ARRAY',
                    '0x10':'SHT_PREINIT_ARRAY',
                    '0x60000000':'SHT_LOOS',
                    '0x6fffffff':'SHT_HIOS',
                    '0x70000000':'SHT_LOPROC',
                    '0x7fffffff':'SHT_HIPROC',
                    '0x80000000':'SHT_LOUSER',
                    '0x8fffffff':'SHT_HIUSER',
                    '0x70000000':'SHT_MIPS_LIST',
                    '0x70000002':'SHT_MIPS_CONFLICT',
                    '0x70000003':'SHT_MIPS_GPTAB',
                    '0x70000004':'SHT_MIPS_UCODE',
                    '0x6ffffff6':'SHT_GNU_HASH',
                    '0x6ffffffe':'SHT_GNU_verdneed',
                    '0x70000001':'0x70000001'
                    }

class Elf32_Ehdr(object):
    def __init__(self):
        self.e_ident = e_ident()
        self.e_type = None
        self.e_machine = None
        self.e_version = None
        self.e_entry = None
        self.e_phoff = None
        self.e_shoff = None
        self.e_flags = None
        self.e_ehsize = None
        self.e_phentsize = None
        self.e_phnum = None
        self.e_shentsize = None
        self.e_shnum = None
        self.e_shstrndx = None
    

class e_ident(object):
    def __init__(self):
        self.file_identification = None
        self.ei_class = None
        self.ei_data = None
        self.ei_version = None
        self.ei_osabi = None
        self.ei_abiversion = None
        self.ei_pad = None
        self.ei_nident = None

    def __str__(self):
        return 'e_ident=[file_identification=%s, ei_class=%d, ei_data=%d, ei_version=%d, ei_osabi=%d, ei_abiversion=%d, ei_pad=%s, ei_nident=%d]' % (
        self.file_identification, self.ei_class, self.ei_data, self.ei_version, self.ei_osabi, self.ei_abiversion, self.ei_pad, self.ei_nident)

class Elf32_Phdr(object):
    def __init__(self):
        self.p_type = None
        self.p_offset = None
        self.p_vaddr = None
        self.p_paddr = None
        self.p_filesz = None
        self.p_memsz = None
        self.p_flags = None
        self.p_align = None


class Elf32_Shdr(object):
    def __init__(self):
        self.sh_name = None
        self.sh_type = None
        self.sh_flags = None
        self.sh_addr = None
        self.sh_offset = None
        self.sh_size = None
        self.sh_link = None
        self.sh_info = None
        self.sh_addralign = None
        self.sh_entsize = None


class Elf32_Dyn(object):
    def __init__(self):
        self.d_tag = None
        self.d_un = None

    def __str__(self):
        return 'Elf32_Dyn=[d_tag=%d, d_un=%d]' % \
               (self.d_tag, self.d_un)


class Elf32_File(object):
    def __init__(self, filePath):
        self.elfFilePath = filePath

        try:
            with open(self.elfFilePath, 'rb') as f:
                self.data = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ | mmap.ACCESS_COPY)
        except FileNotFoundError :
            print("No such file or directory: '%s'" % self.elfFilePath)
            return

        self.Elf32_Ehdr = Elf32_Ehdr()
        self.initElfHeader()

        self.Elf32_Phdr_table = []
        self.initElfProgramHeader()

        self.Elf32_Shdr_table = []
        self.initElfSectionHeader()

        self.Elf32_Dynamic_tabale = []
        self.initDynamicSetion()

    '''
    #define EI_NIDENT 16
    typedef struct elf32_hdr {
    unsigned char e_ident[EI_NIDENT];
    Elf32_Half e_type;
    Elf32_Half e_machine;
    Elf32_Word e_version;
    Elf32_Addr e_entry;
    Elf32_Off e_phoff;
    Elf32_Off e_shoff;
    Elf32_Word e_flags;
    Elf32_Half e_ehsize;
    Elf32_Half e_phentsize;
    Elf32_Half e_phnum;
    Elf32_Half e_shentsize;
    Elf32_Half e_shnum;
    Elf32_Half e_shstrndx;
    } Elf32_Ehdr;
    '''
    def initElfHeader(self):
        self.Elf32_Ehdr.e_ident.file_identification = self.data[0:4]
        self.Elf32_Ehdr.e_ident.ei_class = self.data[4:5]
        self.Elf32_Ehdr.e_ident.ei_data = self.data[5:6]
        self.Elf32_Ehdr.e_ident.ei_version = self.data[6:7]
        self.Elf32_Ehdr.e_ident.ei_osabi = self.data[7:8]
        self.Elf32_Ehdr.e_ident.ei_pad = self.data[8:14]
        self.Elf32_Ehdr.e_ident.ei_nident = self.data[14:15]

        self.Elf32_Ehdr.e_type = struct.unpack('<H', self.data[0x10:0x12])[0]
        self.Elf32_Ehdr.e_machine = struct.unpack('<H', self.data[0x12:0x14])[0]
        self.Elf32_Ehdr.e_version = struct.unpack('<L', self.data[0x14:0x18])[0]
        self.Elf32_Ehdr.e_entry = struct.unpack('<L', self.data[0x18:0x1C])[0]

        self.Elf32_Ehdr.e_phoff = struct.unpack('<L', self.data[0x1C:0x20])[0]
        self.Elf32_Ehdr.e_shoff = struct.unpack('<L', self.data[0x20:0x24])[0]

        self.Elf32_Ehdr.e_flags = struct.unpack('<L', self.data[0x24:0x28])[0]
        self.Elf32_Ehdr.e_ehsize = struct.unpack('<H', self.data[0x28:0x2A])[0]

        self.Elf32_Ehdr.e_phentsize = struct.unpack('<H', self.data[0x2A:0x2C])[0]
        self.Elf32_Ehdr.e_phnum = struct.unpack('<H', self.data[0x2C:0x2E])[0]
        self.Elf32_Ehdr.e_shentsize = struct.unpack('<H', self.data[0x2E:0x30])[0]
        self.Elf32_Ehdr.e_shnum = struct.unpack('<H', self.data[0x30:0x32])[0]

        self.Elf32_Ehdr.e_shstrndx = struct.unpack('<H', self.data[0x32:0x34])[0]
        pass

    def displayELFHeader(self):
        print ('[+] ELF Header:')
        #print ('e_ident:\t%s' % self.Elf32_Ehdr.e_ident)
        print ('e_type: \t%s' % hex(self.Elf32_Ehdr.e_type))
        print ('e_machine:\t%s' % hex(self.Elf32_Ehdr.e_machine))
        print ('e_version:\t%s' % hex(self.Elf32_Ehdr.e_version))
        print ('e_entry:\t%s' % hex(self.Elf32_Ehdr.e_entry))
        print ('e_phoff:\t%s\t//Program header offset' % hex(self.Elf32_Ehdr.e_phoff))
        print ('e_shoff:\t%s\t//Section header offset' % hex(self.Elf32_Ehdr.e_shoff))
        print ('e_flags:\t%s' % hex(self.Elf32_Ehdr.e_flags))
        print ('e_ehsize:\t%s\t//ELF header size' % hex(self.Elf32_Ehdr.e_ehsize))
        print ('e_phentsize:\t%s\t//Program header entry size' % hex(self.Elf32_Ehdr.e_phentsize))
        print ('e_phnum:\t%s\t//Program header number' % hex(self.Elf32_Ehdr.e_phnum))
        print ('e_shentsize:\t%s\t//Section header entry size' % hex(self.Elf32_Ehdr.e_shentsize))
        print ('e_shnum:\t%s\t//Section header number' % hex(self.Elf32_Ehdr.e_shnum))
        print ('e_shstrndx:\t%s\t//Section header string index' % hex(self.Elf32_Ehdr.e_shstrndx))
        print ('')
    
    '''
    typedef struct elf32_shdr {
    Elf32_Word sh_name;
    Elf32_Word sh_type;
    Elf32_Word sh_flags;
    Elf32_Addr sh_addr;
    Elf32_Off sh_offset;
    Elf32_Word sh_size;
    Elf32_Word sh_link;
    Elf32_Word sh_info;
    Elf32_Word sh_addralign;
    Elf32_Word sh_entsize;
    } Elf32_Shdr;
    '''
    def initElfSectionHeader(self):
        section_Offset = self.Elf32_Ehdr.e_shoff
        section_Num = self.Elf32_Ehdr.e_shnum
        section_entsize = self.Elf32_Ehdr.e_shentsize

        if section_Num == 0:
            print("Elf32_Ehdr.e_shnum is None")
            return

        for i in range(section_Num) :
            offset = section_Offset + i * section_entsize
            sh_name = struct.unpack('<L', self.data[offset : offset + 4])[0]
            sh_type = struct.unpack('<L', self.data[offset + 4: offset + 8])[0]
            sh_flags = struct.unpack('<L', self.data[offset + 8: offset + 12])[0]
            sh_addr = struct.unpack('<L', self.data[offset + 12: offset + 16])[0]
            sh_offset = struct.unpack('<L', self.data[offset + 16: offset + 20])[0]
            sh_size = struct.unpack('<L', self.data[offset + 20: offset + 24])[0]
            sh_link = struct.unpack('<L', self.data[offset + 24: offset + 28])[0]
            sh_info = struct.unpack('<L', self.data[offset + 28: offset + 32])[0]
            sh_addralign = struct.unpack('<L', self.data[offset + 32: offset + 36])[0]
            sh_entsize = struct.unpack('<L', self.data[offset + 36: offset + 40])[0]
            self.Elf32_Shdr_table.append({'sh_name': hex(sh_name), 'sh_type': hex(sh_type), 'sh_flags': hex(sh_flags),
                                    'sh_addr': hex(sh_addr), 'sh_offset': hex(sh_offset), 'sh_size': hex(sh_size),
                                    'sh_link': hex(sh_link), 'sh_info': hex(sh_info), 'sh_addralign': hex(sh_addralign),
                                    'sh_entsize': hex(sh_entsize)})
        pass


    def showElfSectionHeader(self):
        count = len(self.Elf32_Shdr_table)
        sec_Offset = self.Elf32_Ehdr.e_shoff

        print('[+] SectionHeader at offset 0x%x contains %d entries:' % (sec_Offset, count))

        for i in range(count):
            print(self.Elf32_Shdr_table[i])
        print("")

    '''
    typedef struct elf32_phdr {
    Elf32_Word p_type;
    Elf32_Off p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    Elf32_Word p_filesz;
    Elf32_Word p_memsz;
    Elf32_Word p_flags;
    Elf32_Word p_align;
    } Elf32_Phdr;
    '''
    def initElfProgramHeader(self):
        program_Offset = self.Elf32_Ehdr.e_phoff
        program_Num = self.Elf32_Ehdr.e_phnum
        program_entsize = self.Elf32_Ehdr.e_phentsize

        for i in range(program_Num):
            offset = program_Offset + i * program_entsize
            p_type = struct.unpack('<L', self.data[offset : offset + 4])[0]
            p_offset = struct.unpack('<L', self.data[offset + 4: offset + 8])[0]
            p_vaddr = struct.unpack('<L', self.data[offset + 8: offset + 12])[0]
            p_paddr = struct.unpack('<L', self.data[offset + 12: offset + 16])[0]
            p_filesz = struct.unpack('<L', self.data[offset + 16: offset + 20])[0]
            p_memsz = struct.unpack('<L', self.data[offset + 20: offset + 24])[0]
            p_flags = struct.unpack('<L', self.data[offset + 24: offset + 28])[0]
            p_align = struct.unpack('<L', self.data[offset + 28: offset + 32])[0]
            self.Elf32_Phdr_table.append({'p_type': hex(p_type), 'p_offset': hex(p_offset), 'p_vaddr': hex(p_vaddr),
                                    'p_paddr': hex(p_paddr), 'p_filesz': hex(p_filesz), 'p_memsz': hex(p_memsz),
                                    'p_flags': hex(p_flags), 'p_align': hex(p_align)})
            pass

        pass
    
    def showElfProgramHeader(self):
        count = len(self.Elf32_Phdr_table)
        program_Offset = self.Elf32_Ehdr.e_phoff

        print('[+] ProgramHeader at offset 0x%x contains %d entries:' % (program_Offset, count))

        for i in range(count):
            print(self.Elf32_Phdr_table[i])
        print("")

    '''
    typedef struct dynamic {
        Elf32_Sword d_tag;     //表的类型
        union {
            Elf32_Sword d_val;   //表的位置
            Elf32_Addr d_ptr;
        } d_un;
    } Elf32_Dyn;
    '''
    def initDynamicSetion(self):
        dynamicSec = self.getDynamicSecFromProgram()
        if dynamicSec == None:
            return 
        
        dynamicSec_p_vaddr = dynamicSec['p_vaddr']
        dynamicSec_offset = self.getDynamicSecOffset(dynamicSec)
        i = 0
        while True:
            offset = dynamicSec_offset + i * 8
            d_tag = struct.unpack('<L', self.data[offset : offset + 4])[0]
            d_un = struct.unpack('<L', self.data[offset + 4: offset + 8])[0]
            if d_tag == 0 and d_un == 0:
                self.Elf32_Dynamic_tabale.append({"d_tag" : hex(d_tag), "d_un" : hex(d_un)})
                break
            self.Elf32_Dynamic_tabale.append({"d_tag" : hex(d_tag), "d_un" : hex(d_un)})
            i = i + 1

        # dynamicSec_sh_addr = dynamicSec['sh_addr']
        # dynamicSec_sh_offset = dynamicSec['sh_offset']
        # dynamicSec_sh_size = int(dynamicSec['sh_size'], 16)
        # dynamicSec_sh_link = dynamicSec['sh_link']
        # dynamicSec_sh_info = dynamicSec['sh_info']
        # dynamicSec_sh_entsize = int(dynamicSec['sh_entsize'], 16)   #如果是一个表，表的每一项的大小

        # dynamicSec_count = dynamicSec_sh_size / dynamicSec_sh_entsize
        # dynamicSec_count = int(dynamicSec_count)
        # for i in range(dynamicSec_count):
        #     offset = int(dynamicSec_sh_offset, 16) + i * dynamicSec_sh_entsize
        #     d_tag = struct.unpack('<L', self.data[offset : offset + 4])[0]
        #     d_un = struct.unpack('<L', self.data[offset + 4: offset + 8])[0]
        #     if d_tag == 0 and d_un == 0:
        #         self.Elf32_Dynamic_tabale.append({"d_tag" : hex(d_tag), "d_un" : hex(d_un)})
        #         break
        #     self.Elf32_Dynamic_tabale.append({"d_tag" : hex(d_tag), "d_un" : hex(d_un)})
        pass


    def showDynamicSection(self):
        dynamicSec = self.getDynamicSecFromProgram()
        if dynamicSec == None:
            return

        dynamicSec_offset = self.getDynamicSecOffset(dynamicSec) 
        count = len(self.Elf32_Dynamic_tabale)

        print('[+] Dynamic section at offset 0x%x contains %d entries:' % (dynamicSec_offset, count))
        print("  Tag\t\tType\t\tName/Value")

        for i in range(count):
            type_index = self.Elf32_Dynamic_tabale[i]['d_tag']
            type = DYNAMIC_TYPE[int(type_index,16)]
            d_un = self.Elf32_Dynamic_tabale[i]['d_un']

            mat = "  {:10}\t{:10}\t{:8}"
            print(mat.format(type_index, type, d_un))
            pass

        print("")


    def getSectionByType(self, type):
        for i in range(len(self.Elf32_Shdr_table)):
            index = self.Elf32_Shdr_table[i]['sh_type']
            section_type = SH_TYPE_MAP_LIST[index]
            #print('sh_type  %d %s' % (i, section_type))
            if section_type == type:
                return self.Elf32_Shdr_table[i]
        return None

    # add code
    def getDynamicSecFromProgram(self):
        count = len(self.Elf32_Phdr_table)
        for i in range(count):
            type = int(self.Elf32_Phdr_table[i]['p_type'], 16)
            if type == 2:
                return self.Elf32_Phdr_table[i]    
        return None


    def getDynamicSecOffset(self, dynamicTable):
        count = len(self.Elf32_Phdr_table)
        data_rva = int(dynamicTable['p_vaddr'], 16)
        
        for i in range(count):
            type = int(self.Elf32_Phdr_table[i]['p_type'], 16)
            if type == 1:
                star_fa = int(self.Elf32_Phdr_table[i]['p_offset'], 16)
                start_rva = int(self.Elf32_Phdr_table[i]['p_vaddr'], 16)
                mmap_size = int(self.Elf32_Phdr_table[i]['p_memsz'], 16)
                offset = self.rva2fa(start_rva, star_fa, mmap_size, data_rva)
                if offset != 0:
                    return offset   
        return None


    def rva2fa(self, start_rva, star_fa, mmap_size, data_rva):
        if (data_rva > start_rva) and (data_rva < (start_rva + mmap_size)):
            off = start_rva - star_fa
            return data_rva - off
        else:
            return 0


    def getElfHeader(self):
        return self.Elf32_Ehdr


    def getElfSectionHeader(self):
        return self.Elf32_Shdr_table


    def getElfProgramHeader(self):
        return self.Elf32_Phdr_table


    def getElfDynamicSection(self):
        return self.Elf32_Dynamic_tabale


def main():
    argCount = len(sys.argv)
    if argCount < 2 :
        print("Parser elfFile need filePath!")
        return
    
    filePath = sys.argv[1]

    file = Elf32_File(filePath)
    file.displayELFHeader()
    file.showElfSectionHeader()
    file.showElfProgramHeader()
    file.showDynamicSection()

    pass


if __name__ == '__main__':
    main()