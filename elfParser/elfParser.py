
# -*- coding: utf-8 -*-

from locale import atoi
import sys
import mmap
import struct


'''
#define PF_R 0x4
#define PF_W 0x2
#define PF_X 0x1

#define DT_NULL 0       //常用来表示dynamic 节的结束
#define DT_NEEDED 1     //用来保存需要链接的库的名称
    				    //DT_STRTAB + 该表中保存的偏移
           
#define DT_PLTRELSZ 2   //.rel.plt节的大小
#define DT_PLTGOT 3     //.rel.plt (重定位API)需要填写到内存的地址
#define DT_HASH 4       //保存了哈希表地址
#define DT_STRTAB 5     //保存了字符串表地址，动态符号字符串表
#define DT_SYMTAB 6     //保存了符号表地址，动态符号表

#define DT_RELA 7       //.rel.dyn (重定位全局变量)的地址
#define DT_RELASZ 8     //.rel.dyn (重定位全局变量)的大小
#define DT_RELAENT 9    //.rel.dyn (重定位全局变量)每一项的大小
    					//重定位表的结构按照Elf32_Rela解析
         
#define DT_STRSZ 10     //字符串表的大小
#define DT_SYMENT 11    //符号表的大小
#define DT_INIT 12      //初始化表
#define DT_FINI 13      //反初始化表
#define DT_SONAME 14    //保存了该so的文件名称
#define DT_RPATH 15     //搜索库的搜索目录字符串
#define DT_SYMBOLIC 16

#define DT_REL 17       //.rel.dyn (重定位全局变量)的地址
#define DT_RELSZ 18     //.rel.dyn (重定位全局变量)的大小
#define DT_RELENT 19    //.rel.dyn (重定位全局变量)每一项的大小
    					//重定位表的结构按照Elf32_Rel解析
         
#define DT_PLTREL 20    //指定重定位表的解析格式
#define DT_DEBUG 21     //是否被调试使用
#define DT_TEXTREL 22   // 代码重定位
#define DT_JMPREL 23    //.rel.plt 在文件中的偏移
#define	DT_BIND_NOW	24		    /* Process relocations of object */
#define	DT_INIT_ARRAY	25		/* Array with addresses of init fct */
#define	DT_FINI_ARRAY	26		/* Array with addresses of fini fct */
#define	DT_INIT_ARRAYSZ	27		/* Size in bytes of DT_INIT_ARRAY */
#define	DT_FINI_ARRAYSZ	28		/* Size in bytes of DT_FINI_ARRAY */
#define DT_RUNPATH	29		    /* Library search path */
#define DT_FLAGS	30		    /* Flags for the object being loaded */

#define DT_PREINIT_ARRAY 32		/* Array with addresses of preinit fct*/
#define DT_PREINIT_ARRAYSZ 33	/* size in bytes of DT_PREINIT_ARRAY */

'''

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
        dynamicSec = self.getSectionByType('SHT_DYNAMIC')
        if dynamicSec == None:
            return
        
        dynamicSec_sh_addr = dynamicSec['sh_addr']
        dynamicSec_sh_offset = dynamicSec['sh_offset']
        dynamicSec_sh_size = int(dynamicSec['sh_size'], 16)
        dynamicSec_sh_link = dynamicSec['sh_link']
        dynamicSec_sh_info = dynamicSec['sh_info']
        dynamicSec_sh_entsize = int(dynamicSec['sh_entsize'], 16)   #如果是一个表，表的每一项的大小

        dynamicSec_count = dynamicSec_sh_size / dynamicSec_sh_entsize
        dynamicSec_count = int(dynamicSec_count)
        for i in range(dynamicSec_count):
            offset = int(dynamicSec_sh_offset, 16) + i * dynamicSec_sh_entsize
            d_tag = struct.unpack('<L', self.data[offset : offset + 4])[0]
            d_un = struct.unpack('<L', self.data[offset + 4: offset + 8])[0]
            if d_tag == 0 and d_un == 0:
                self.Elf32_Dynamic_tabale.append({"d_tag" : hex(d_tag), "d_un" : hex(d_un)})
                break
            self.Elf32_Dynamic_tabale.append({"d_tag" : hex(d_tag), "d_un" : hex(d_un)})

        pass

    def showDynamicSection(self):
        dynamicSec = self.getSectionByType('SHT_DYNAMIC')
        if dynamicSec == None:
            return

        dynamicSec_sh_offset = dynamicSec['sh_offset']   
        count = len(self.Elf32_Dynamic_tabale)

        print('[+] Dynamic section at offset %s contains %d entries:' % (dynamicSec_sh_offset, count))
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