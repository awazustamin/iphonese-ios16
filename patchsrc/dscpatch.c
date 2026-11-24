/* Pattern-based iOS16 ARM64 DSC subcache patcher.
 * cc -std=c11 -O2 -Wall -Wextra -Wpedantic dscpatch.c -o dscpatch
 * ./dscpatch input-cache-or-subcache output-patched
 * Auto-detects supported images. RFS .13 needs sibling .05.
 * PhotosFormats uses a 20B82-specific CFString anchor in .27.dylddata.
 * Native macOS build uses CommonCrypto for CodeDirectory SHA-256 validation.
 */
#define _POSIX_C_SOURCE 200809L
#include <CommonCrypto/CommonDigest.h>
#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#define N(a) (sizeof(a)/sizeof((a)[0]))
typedef struct {uint32_t v,m;} Word;
typedef struct {uint64_t va,size,off;uint32_t prot;} Mapping;
typedef struct {size_t header,header_end;uint64_t va,text_end;size_t code,code_size;} Image;
static unsigned char *b;static size_t length;static Mapping maps[64];static size_t nm;
static void die(const char *s){fprintf(stderr,"dscpatch: %s\n",s);exit(1);}
static int fits(uint64_t o,uint64_t n){return o<=length&&n<=length-o;}
static uint32_t u32(size_t p){if(!fits(p,4))die("truncated field");return (uint32_t)b[p]|(uint32_t)b[p+1]<<8|(uint32_t)b[p+2]<<16|(uint32_t)b[p+3]<<24;}
static uint64_t u64(size_t p){return u32(p)|(uint64_t)u32(p+4)<<32;}
static uint32_t be32(size_t p){uint32_t w=u32(p);return (w>>24)|((w>>8)&0xff00)|((w<<8)&0xff0000)|(w<<24);}
static void put32(size_t p,uint32_t w){if(!fits(p,4))die("patch outside input");for(unsigned i=0;i<4;i++)b[p+i]=(unsigned char)(w>>(i*8));}
static uint64_t va(size_t o){for(size_t i=0;i<nm;i++)if(o>=maps[i].off&&o-maps[i].off<maps[i].size)return maps[i].va+o-maps[i].off;die("unmapped file offset");return 0;}
static size_t offset(uint64_t a,size_t n){for(size_t i=0;i<nm;i++)if(a>=maps[i].va&&a-maps[i].va<=maps[i].size&&n<=maps[i].size-(a-maps[i].va))return (size_t)(maps[i].off+a-maps[i].va);die("VM target not in input subcache");return 0;}
static int mapped_exec(size_t o,size_t n){for(size_t i=0;i<nm;i++)if((maps[i].prot&4)&&o>=maps[i].off&&o-maps[i].off<=maps[i].size&&n<=maps[i].size-(o-maps[i].off))return 1;return 0;}
static int image_at(size_t h,const char *want,Image *out){
 if(!fits(h,32)||u32(h)!=0xfeedfacf||u32(h+4)!=0x0100000c||u32(h+12)!=6)return 0;
 uint32_t count=u32(h+16),bytes=u32(h+20);if(count>256||!fits(h+32,bytes)||!mapped_exec(h,32+bytes))return 0;
 size_t p=h+32,end=p+bytes;int id=0;Image im={h,end,va(h),0,0,0};
 for(uint32_t i=0;i<count;i++){
  if(p>end||end-p<8)return 0;uint32_t cmd=u32(p),sz=u32(p+4);if(sz<8||(sz&7)||sz>end-p)return 0;
  if(cmd==0xd){if(sz<24)return 0;uint32_t s=u32(p+8);if(s<24||s>=sz||!memchr(b+p+s,0,sz-s))return 0;if(!strcmp((char *)b+p+s,want))id++;}
  if(cmd==25){
   if(sz<72||u32(p+64)>(sz-72)/80)return 0;
   if(!strncmp((char *)b+p+8,"__TEXT",16)){
    uint64_t v=u64(p+24),size=u64(p+48);if(v!=im.va||size>UINT64_MAX-v)return 0;im.text_end=v+size;
    for(uint32_t j=0;j<u32(p+64);j++){
     size_t q=p+72+(size_t)j*80;uint64_t a=u64(q+32),n=u64(q+40);
     if(a<v||a-v>size||n>size-(a-v))return 0;
     if(!strncmp((char *)b+q,"__text",16)){if(im.code_size)return 0;im.code=offset(a,(size_t)n);im.code_size=(size_t)n;}
    }
   }
  }
  p+=sz;
 }
 if(p!=end||id!=1||!im.code_size||!mapped_exec(im.code,im.code_size))return 0;
 *out=im;return 1;
}
static int find_image(const char *name,Image *out){size_t hits=0;for(size_t i=0;i<nm;i++)if(maps[i].prot&4){
 size_t begin=(size_t)maps[i].off,end=begin+(size_t)maps[i].size;
 for(size_t p=(begin+3)&~(size_t)3;p+32<=end;p+=4)if(u32(p)==0xfeedfacf){Image im;if(image_at(p,name,&im)){*out=im;hits++;}}
 }if(hits>1)die("ambiguous target image");return hits==1;}
static size_t match(Image im,const Word *sig,size_t count,const char *name){
 size_t hits=0,found=0;if(count>im.code_size/4)die("code section too small");
 for(size_t p=im.code;p<=im.code+im.code_size-count*4;p+=4){size_t i=0;for(;i<count;i++)if((u32(p+i*4)&sig[i].m)!=sig[i].v)break;if(i==count){hits++;found=p;}}
 if(hits!=1){fprintf(stderr,"dscpatch: %s: expected one signature, found %zu; no output\n",name,hits);exit(1);}return found;
}
static uint64_t page(uint32_t w,uint64_t pc){int64_t v=(((w>>5)&0x7ffff)<<2)|((w>>29)&3);if(v&(1<<20))v-=1<<21;return (pc&~UINT64_C(4095))+(uint64_t)(v*4096);}
static uint64_t target(uint32_t w,uint64_t pc){int64_t v=w&0x3ffffff;if(v&(1<<25))v-=1<<26;return pc+(uint64_t)(v*4);}
static uint32_t branch(uint64_t from,uint64_t to,int cond){int64_t d=(int64_t)to-(int64_t)from;unsigned bits=cond<0?26:19;if(d%4||d/4<-(INT64_C(1)<<(bits-1))||d/4>=(INT64_C(1)<<(bits-1)))die("branch out of range");uint32_t v=(uint32_t)(d/4)&((1u<<bits)-1);return cond<0?0x14000000u|v:0x54000000u|(v<<5)|(unsigned)cond;}
static const Word nano_sig[] = {
{0x94000000u,0xfc000000u},
{0x90000002u,0x9f00001fu},
{0x91000042u,0xffc003ffu},
{0xf90007e0u,0xffffffffu},
{0x94000000u,0xfc000000u},
{0x36000060u,0xffffffffu},
{0x52800020u,0xffffffffu},
{0x14000000u,0xfc000000u},
{0x90000000u,0x9f00001fu},
{0x91000000u,0xffc003ffu},
{0x94000000u,0xfc000000u},
{0x90000008u,0x9f00001fu},
{0x3907e100u,0xffffffffu},
{0xf94007e0u,0xffffffffu},
{0xa9417bfdu,0xffffffffu},
{0x910003ffu,0xffc003ffu},
{0x14000000u,0xfc000000u},
};
static const Word sleep_entry_sig[] = {
{0xd105c3ffu,0xffffffffu},
{0xa9116ffcu,0xffffffffu},
{0xa91267fau,0xffffffffu},
{0xa9135ff8u,0xffffffffu},
{0xa91457f6u,0xffffffffu},
{0xa9154ff4u,0xffffffffu},
{0xa9167bfdu,0xffffffffu},
{0x910003fdu,0xffc003ffu},
{0xaa0003f3u,0xffffffffu},
{0x90000008u,0x9f00001fu},
{0xf941fd08u,0xffffffffu},
{0xf9400108u,0xffffffffu},
{0xf81983a8u,0xffffffffu},
{0x94000000u,0xfc000000u},
{0x37000f40u,0xffffffffu},
{0x91000275u,0xffc003ffu},
};
static const Word sleep_target_sig[] = {
{0xd10203ffu,0xffffffffu},
{0xa90557f6u,0xffffffffu},
{0xa9064ff4u,0xffffffffu},
{0xa9077bfdu,0xffffffffu},
{0x910003fdu,0xffc003ffu},
{0xaa0003f3u,0xffffffffu},
{0x90000008u,0x9f00001fu},
{0xf941fd08u,0xffffffffu},
{0xf9400108u,0xffffffffu},
{0xf81d83a8u,0xffffffffu},
{0x52800080u,0xffffffffu},
{0x94000000u,0xfc000000u},
{0x94000000u,0xfc000000u},
{0xaa0003f4u,0xffffffffu},
{0x52800001u,0xffffffffu},
{0x94000000u,0xfc000000u},
{0x34000000u,0xff00001fu},
{0xaa1303e0u,0xffffffffu},
};
static const Word radio_sig[] = {
{0xf94001cbu,0xffffffffu},
{0xf85983acu,0xffffffffu},
{0xeb0c017fu,0xffffffffu},
{0x54000001u,0xff00001fu},
{0x7100153fu,0xffffffffu},
{0x54000000u,0xff00001fu},
{0x7100155fu,0xffffffffu},
{0x54000000u,0xff00001fu},
{0x6b09015fu,0xffffffffu},
{0x54000000u,0xff00001fu},
{0x3400000au,0xff00001fu},
{0x34000009u,0xff00001fu},
{0x90000009u,0x9f00001fu},
{0xb900093fu,0xffffffffu},
{0x90000009u,0x9f00001fu},
{0xb9000d3fu,0xffffffffu},
{0x90000009u,0x9f00001fu},
{0xb900113fu,0xffffffffu},
{0xb900591fu,0xffffffffu},
{0x14000000u,0xfc000000u},
};
static const Word j72s_sig[] = {
{0x90000008u,0x9f00001fu},
{0x52800729u,0xffffffffu},
{0x14000000u,0xfc000000u},
{0x90000008u,0x9f00001fu},
{0x52800889u,0xffffffffu},
{0xb9000909u,0xffffffffu},
{0x90000008u,0x9f00001fu},
{0x52800029u,0xffffffffu},
{0xb9000d09u,0xffffffffu},
{0x90000008u,0x9f00001fu},
{0x14000000u,0xfc000000u},
};
typedef struct {size_t at;uint32_t word;} Edit;
static Edit edits[512];static size_t ne;
static void edit(size_t at,uint32_t word){if(ne==N(edits)||!mapped_exec(at,4))die("invalid code edit");for(size_t i=0;i<ne;i++)if(edits[i].at==at)die("overlapping edit");edits[ne++]=(Edit){at,word};}

/* N69 camera profile: semantic SE15 field translation into the native16 ABI.
 * Newer unsupported features remain disabled; unavailable limits retain native
 * sentinels. No embedded absolute pointers: the release string is ADR-derived. */
static const uint32_t n69_camera_profile[]={0x00010101u,0x00000001u,0x00000000u,0x00000000u,0x00000000u,0x00000000u,0x00000100u,0x00000000u,0x00000000u,0x00000000u,0x00000000u,0x00000000u,0x01010101u,0x00000000u,0x00000000u,0x01010001u,0x01010101u,0x01010100u,0x00000000u,0x00000000u,0x00010101u,0x7fc00000u,0x40a00000u,0x7fc00000u,0x7fc00000u,0x00000000u,0xffffffffu,0x7fffffffu,0xffffffffu,0x7fffffffu,0x00000001u,0x00000000u,0xffffffffu,0x7fffffffu,0x00000001u,0x00000000u,0x000003e7u,0x00000000u,0xffffffffu,0x7fffffffu,0xffffffffu,0x7fffffffu,0xffffffffu,0x7fffffffu,0x00000001u,0x00000000u,0x00000064u,0x00000000u,0xffffffffu,0x7fffffffu,0xffffffffu,0x7fffffffu,0x0000001eu,0x00000000u,0x00000078u,0x00000000u,0x000000f0u,0x00000000u,0x00000003u,0x00000000u,0x00000064u,0x00000000u,0x0000003cu,0x00000000u,0x0000001eu,0x00000000u,0x0000003cu,0x00000000u,0xffffffffu,0x7fffffffu,0xffffffffu,0x7fffffffu,0xffffffffu,0x7fffffffu,0xffffffffu,0x7fffffffu,0x00000000u,0x00000000u};
static const uint32_t camera_profile_loads[]={0x394002e2u,0x394006e2u,0x39400ae2u,0x39400ee2u,0x394012e2u,0x394016e2u,0x39401ae2u,0x39401ee2u,0x394022e2u,0x394026e2u,0x39402ae2u,0x39402ee2u,0x394032e2u,0x394036e2u,0x39403ae2u,0x39403ee2u,0x394042e2u,0x394046e2u,0x39404ae2u,0x39404ee2u,0x394052e2u,0x394056e2u,0x39405ae2u,0x39405ee2u,0x394062e2u,0x394066e2u,0x39406ae2u,0x39406ee2u,0x394072e2u,0x394076e2u,0x39407ae2u,0x39407ee2u,0x394082e2u,0x394086e2u,0x39408ae2u,0x39408ee2u,0x394092e2u,0x394096e2u,0x39409ae2u,0x39409ee2u,0x3940a2e2u,0x3940a6e2u,0x3940aae2u,0x3940aee2u,0x3940b2e2u,0x3940b6e2u,0x3940bae2u,0x3940bee2u,0x3940c2e2u,0x3940c6e2u,0x3940cae2u,0x3940cee2u,0x3940d2e2u,0x3940d6e2u,0x3940dae2u,0x3940dee2u,0x3940e2e2u,0x3940e6e2u,0x3940eae2u,0x3940eee2u,0x3940f2e2u,0x3940f6e2u,0x3940fae2u,0x3940fee2u,0x394102e2u,0x394106e2u,0x39410ae2u,0x39410ee2u,0x394112e2u,0x394116e2u,0x39411ae2u,0x39411ee2u,0x394122e2u,0x394126e2u,0x39412ae2u,0x39412ee2u,0x394132e2u,0x394136e2u,0x39413ae2u,0x39413ee2u,0x394142e2u,0x394146e2u,0x39414ae2u,0xbd4056e0u,0xbd405ae0u,0xbd405ee0u,0xbd4062e0u,0xf94036e2u,0xf9403ae2u,0xf9403ee2u,0xf94042e2u,0xf94046e2u,0xf9404ae2u,0xf9404ee2u,0xf94052e2u,0xf94056e2u,0xf9405ae2u,0xf9405ee2u,0xf94062e2u,0xf94066e2u,0xf9406ae2u,0xf9406ee2u,0xf94072e2u,0xf94076e2u,0xf9407ae2u,0xf9407ee2u,0xf94082e2u,0xf94086e2u,0xf9408ae2u,0xf9408ee2u,0xf94092e2u,0xf94096e2u,0xf9409ae2u};
static const Word camera_loop_sig[]={{0xd280001au,0xffffffffu},{0x90000019u,0x9f00001fu},{0x9000001bu,0x9f00001fu},{0x9100037bu,0xffc003ffu},{0x90000018u,0x9f00001fu},{0x91000318u,0xffc003ffu},{0xf947e720u,0xffffffffu},{0xf87a6b62u,0xffffffffu},{0x94000000u,0xfc000000u},{0xaa1803e2u,0xffffffffu},{0x94000000u,0xfc000000u},{0xaa1703e2u,0xffffffffu},{0x94000000u,0xfc000000u},{0x37000000u,0xfff8001fu},{0x9100035au,0xffc003ffu},{0xf10a435fu,0xffffffffu},{0x54000001u,0xff00001fu},{0x14000000u,0xfc000000u},{0x8b1a0368u,0xffffffffu},{0xf9400517u,0xffffffffu}};
static const Word camera_release_sig[]={
 {0xf9409ae2u,0xffffffffu}, {0xb4000002u,0xff00001fu},
 {0xf9400320u,0xffc003ffu}, {0x94000000u,0xfc000000u},
 {0xaa0003e2u,0xffffffffu}, {0x90000003u,0x9f00001fu},
 {0x91000063u,0xffc003ffu}
};
static int64_t sx(uint32_t v,unsigned bits){return (int64_t)(v^(1u<<(bits-1)))-(int64_t)(1u<<(bits-1));}
static uint32_t adr(unsigned reg,uint64_t pc,uint64_t dest){
 int64_t d=(int64_t)dest-(int64_t)pc;if(reg>30||d<-(1<<20)||d>=(1<<20))die("camera ADR range");
 uint32_t v=(uint32_t)d&0x1fffff;return 0x10000000u|((v&3)<<29)|((v>>2)<<5)|reg;
}
static size_t header_gap(Image im,size_t need){
 size_t first=im.code,p=im.header+32;uint32_t count=u32(im.header+16);
 for(uint32_t i=0;i<count;i++){uint32_t cmd=u32(p),n=u32(p+4);
  if(cmd==25)for(uint32_t j=0;j<u32(p+64);j++){size_t s=p+72+(size_t)j*80;uint64_t a=u64(s+32),z=u64(s+40);
   if(z&&a>=im.va&&a<im.text_end){size_t o=offset(a,1);if(o<first)first=o;}}
  p+=n;
 }
 size_t start=(im.header_end+7)&~(size_t)7;
 if(first<start||need>first-start||!mapped_exec(start,need))die("no protected camera header space");
 for(size_t i=0;i<need;i++)if(b[start+i])die("camera header space is occupied");
 /* No declared section overlaps this region; all bytes and hooks are queued
  * before publication. No slide/fixup-chain pointer is introduced. */
 return start;
}

static void camera(Image im){
 size_t ctx=match(im,camera_loop_sig,N(camera_loop_sig),"AVFCapture product capability loop");
 size_t rel=match(im,camera_release_sig,N(camera_release_sig),"AVFCapture release-string field");
 uint64_t cv0=va(ctx),ret=target(u32(ctx+17*4),cv0+17*4),load=cv0+20*4;
 if(rel<=ctx+80 || ret<=va(rel) || ret>=im.text_end ||
    va(rel+4)+(uint64_t)(sx((u32(rel+4)>>5)&0x7ffff,19)*4)!=ret ||
    (cv0+13*4+(uint64_t)(sx((u32(ctx+13*4)>>5)&0x3fff,14)*4))!=cv0+18*4 ||
    (cv0+16*4+(uint64_t)(sx((u32(ctx+16*4)>>5)&0x7ffff,19)*4))!=cv0+6*4)die("camera loop/release topology mismatch");
 /* Validate the unchanged native exit rather than accepting a redirected miss. */
 if(u32(ctx+14*4)!=0x9100435au)die("camera group stride mismatch");
 size_t loads=0;for(size_t p=ctx+20*4;va(p)<ret;p+=4){uint32_t w=u32(p),opc=(w>>22)&3;
  if((w&0x3b000000u)==0x39000000u&&opc&&(w>>5&31)==23&&((w&31)==2||((w&(1u<<26))&&(w&31)==0))){
   if(loads==N(camera_profile_loads)||w!=camera_profile_loads[loads++])die("camera profile field layout mismatch");}}
 if(loads!=N(camera_profile_loads))die("incomplete camera profile field layout");
 size_t ep=offset(ret,28);static const uint32_t exit_words[]={0xa9457bfd,0xa9444ff4,0xa94357f6,0xa9425ff8,0xa94167fa,0xa8c66ffc,0xd65f03c0};
 for(size_t i=0;i<N(exit_words);i++)if(u32(ep+i*4)!=exit_words[i])die("camera exit mismatch or already patched");
 uint64_t calls[3];size_t ci[]={8,10,12};
 for(size_t i=0;i<3;i++){calls[i]=target(u32(ctx+ci[i]*4),cv0+ci[i]*4);if(calls[i]<im.va||calls[i]>=im.text_end||!mapped_exec(offset(calls[i],4),4))die("camera selector calls outside image");}
 size_t cave=header_gap(im,404);uint64_t cv=va(cave),helper=cv+44,profile=cv+72,group=cv+384,release=cv+396;
 uint32_t stub[]={u32(ctx+6*4),adr(2,cv+4,group),branch(cv+8,calls[0],-1)|0x80000000u,
  u32(ctx+9*4),branch(cv+16,calls[1],-1)|0x80000000u,u32(ctx+11*4),branch(cv+24,calls[2],-1)|0x80000000u,
  0x37000040u,branch(cv+32,ret,-1),adr(23,cv+36,profile),branch(cv+40,load,-1),
  adr(2,helper,profile),0xeb0202ffu,branch(helper+8,helper+20,0),u32(rel),0xd65f03c0u,
  adr(2,helper+20,release),0xd65f03c0u};
 for(size_t i=0;i<N(stub);i++)edit(cave+i*4,stub[i]);
 for(size_t i=0;i<N(n69_camera_profile);i++)edit(cave+72+i*4,n69_camera_profile[i]);
 static const unsigned char names[12]="N69-N69u";static const unsigned char release_name[8]="iOS 9.3";
 for(size_t i=0;i<12;i+=4){uint32_t w=0;for(unsigned j=0;j<4;j++)w|=(uint32_t)names[i+j]<<(j*8);edit(cave+384+i,w);}
 for(size_t i=0;i<8;i+=4){uint32_t w=0;for(unsigned j=0;j<4;j++)w|=(uint32_t)release_name[i+j]<<(j*8);edit(cave+396+i,w);}
 edit(ctx+17*4,branch(cv0+17*4,cv,-1));edit(rel,branch(va(rel),helper,-1)|0x80000000u);
 printf("Camera: N69/N69u SE capability profile; selector +0x%zx, release +0x%zx, payload +0x%zx (404 bytes)\n",ctx+17*4,rel,cave);
}

/* The proxy reader uses the archived filename without a type hint. */
static void photo_proxy(Image im,const char *input){
 static const uint64_t png_string=UINT64_C(0x1d74345d0);
 static const uint64_t png_bytes=UINT64_C(0x1a0063ca9);
 static const uint64_t proxy_bytes=UINT64_C(0x1a01a034d);
 static const Word writer[]={
  {0x901d8568u,~0u},{0xf942a108u,~0u},{0xf9400100u,~0u},
  {0x94030edcu,~0u},{0x9489b365u,~0u},{0xaa0003f4u,~0u},
  {0xaa1303e0u,~0u},{0xaa1403e1u,~0u},{0x52800022u,~0u},
  {0xd2800003u,~0u},{0x9489b020u,~0u}
 };
 size_t q=match(im,writer,N(writer),"PhotosFormats proxy ImageIO writer (20B82)");
 size_t proxy=offset(proxy_bytes,11);
 if(proxy_bytes<im.va||proxy_bytes+11>im.text_end||
    memcmp(b+proxy,"proxy.heic",11)||memcmp(b+offset(png_bytes,11),"public.png",11))
  die("PhotosFormats proxy string anchors differ");

 /* Validate the CFString anchors without modifying the data subcache. */
 size_t n=strlen(input);
 if(n<3||strcmp(input+n-3,".09"))die("PhotosFormats requires .09 and sibling .27.dylddata");
 char *path=malloc(n+10);if(!path)die("out of memory");
 memcpy(path,input,n-3);strcpy(path+n-3,".27.dylddata");
 FILE *f=fopen(path,"rb");free(path);if(!f)die("missing PhotosFormats data subcache");
 static const unsigned char png_cf[]={0x08,0xcb,0xf2,0xe1,1,4,0,0,0xc8,7,0,0,0,0,0,0,
  0xa9,0x3c,0x06,0xa0,1,4,0,0,10,0,0,0,0,0,0,0};
 static const unsigned char proxy_cf[]={0x08,0xcb,0xf2,0xe1,1,4,0,0,0xc8,7,0,0,0,0,0,0,
  0x4d,0x03,0x1a,0xa0,1,4,0,0,10,0,0,0,0,0,0,0};
 unsigned char a[32],c[32];
 if(fseek(f,0x22f85d0,SEEK_SET)||fread(a,1,sizeof a,f)!=sizeof a||
    fseek(f,0x232f6b0,SEEK_SET)||fread(c,1,sizeof c,f)!=sizeof c||fclose(f)||
    memcmp(a,png_cf,sizeof a)||memcmp(c,proxy_cf,sizeof c))
  die("PhotosFormats data subcache anchors differ");

 /* Load public.png directly and preserve the writer's ownership calls. */
 int64_t delta=((int64_t)(png_string&~UINT64_C(4095))-(int64_t)(va(q)&~UINT64_C(4095)))/4096;
 if(delta<-(1<<20)||delta>=(1<<20))die("PhotosFormats PNG ADRP range");
 uint32_t v=(uint32_t)delta&0x1fffff;
 edit(q,0x90000000u|((v&3)<<29)|((v>>2)<<5));
 edit(q+4,0x91000000u|((uint32_t)(png_string&4095)<<10));
 edit(q+8,0xd503201fu);edit(q+12,0xd503201fu);
 /* Same length as proxy.heic, so the cached CFString stays valid. */
 static const char renamed[]="proxy_.png";
 for(size_t addr=(proxy+5)&~(size_t)3;addr<=((proxy+9)&~(size_t)3);addr+=4){
  uint32_t w=u32(addr);
  for(unsigned i=0;i<4;i++)if(addr+i>=proxy+5&&addr+i<proxy+10){
   w=(w&~(0xffu<<(i*8)))|((uint32_t)(unsigned char)renamed[addr+i-proxy]<<(i*8));}
  edit(addr,w);
 }
 printf("PhotosFormats: wallpaper proxy -> PNG at +0x%zx\n",q);
}

static void photo_layer_name(Image im,uint64_t where,const char *name){
 size_t n=strlen(name);
 if(where<im.va||where>im.text_end||n+1>im.text_end-where||
    n<5||strcmp(name+n-5,".HEIC"))die("invalid layer filename anchor");
 size_t p=offset(where,n+1),end=p+n;
 if(memcmp(b+p,name,n+1))die("PhotosFormats layer filename differs");
 /* Keep the original CFString length while giving the file a PNG suffix. */
 static const char suffix[]="_.PNG";
 for(size_t at=(end-5)&~(size_t)3;at<end;at+=4){
  uint32_t w=u32(at);
  for(unsigned i=0;i<4;i++)if(at+i>=end-5&&at+i<end)
   w=(w&~(0xffu<<(i*8)))|((uint32_t)suffix[at+i-(end-5)]<<(i*8));
  edit(at,w);
 }
}

/* Bridge the layer archive's CVPixelBuffer ABI to the CGImage helpers. */
static void photo_layers(Image im){
 static const Word save_site[]={
  {0xaa1403e0,~0u},{0x94030404,~0u},{0xaa1c03e1,~0u},
  {0xaa1603e2,~0u},{0x94000ba8,~0u},{0x350026c0,~0u}
 };
 static const Word read_site[]={
  {0x940002c3,~0u},{0xf90017fa,~0u},{0x34001340,~0u},{0xd01eca28,~0u}
 };
 size_t s=match(im,save_site,N(save_site),"PhotosFormats layer writer (20B82)")+16;
 size_t r=match(im,read_site,N(read_site),"PhotosFormats layer reader (20B82)");
 static const uint64_t png_save=UINT64_C(0x1a010ea04),image_read=UINT64_C(0x1a010ec24);
 uint64_t old_save=target(u32(s),va(s)),old_read=target(u32(r),va(r));
 const uint64_t entries[]={png_save,image_read,old_save,old_read};
 const uint32_t prologues[]={0xd101c3ff,0xd101c3ff,0xd10283ff,0xd10183ff};
 for(size_t i=0;i<N(entries);i++)
  if(entries[i]<va(im.code)||entries[i]-va(im.code)>=im.code_size||
     u32(offset(entries[i],4))!=prologues[i])die("PhotosFormats layer call target differs");
 /* The direct calls below use these two helper implementations without
  * a receiver: neither consumes self or _cmd on the nil NSError path. */
 if(u32(offset(png_save+24,4))!=0xaa0403f5||
    u32(offset(image_read+24,4))!=0xaa0303f4)die("PhotosFormats ImageIO helper ABI differs");
 /* Fill BL relocations and call thunks after choosing the bridge address. */
 enum { surface_at=0x210 };
 uint32_t bridge[]={
  /* Writer: VTCreateCGImageFromCVPixelBuffer -> PNG writer -> CGImageRelease. */
  0xa9bd7bfd,0x910003fd,0xa90153f3,0xaa0103f3,0xf90013ff,0xaa1f03e1,0x910083e2,0,
  0x2a0003f4,0xf94013e2,0x35000134,0xb40000e2,0xaa1303e3,0xaa1f03e4,0,0x7100001f,
  0x1a9f17f4,0x14000002,0x52800034,0xf94013e0,0xb4000040,0,0x2a1403e0,0xa94153f3,
  0xa8c37bfd,0xd65f03c0,
  /* Reader: try the native decoder first. ImageIO fallback returns a +1
   * IOSurface-backed buffer with premultiplied little-endian BGRA.
   * On failure keep the native decoder's OSStatus and release temporaries. */
  0xa9b97bfd,0x910003fd,0xa90153f3,0xa9025bf5,0xa90363f7,0xa9046bf9,0xaa0003f3,0xaa0403f4,
  0,0x2a0003f5,0x34000b35,0xb4000b14,0xaa1303e2,0xaa1f03e3,0,0xb4000a80,
  0xaa0003f6,0,0xaa0003f7,0xaa1603e0,0,0xaa0003f8,0xb4000977,0xb4000958,
  /* Bound decoded dimensions and limit the BGRA allocation to 64 MiB. */
  0xf1400aff,0x54000908,0xf1400b1f,0x540008c8,0x9b187ee8,0xd2a02009,0xeb09011f,0x54000848,
  0xf9002bff,0xaa1f03e0,0xaa1703e1,0xaa1803e2,0x528a4823,0x72a848e3,0xaa1f03e4,0x910143e5,
  0,0x35000700,0xf9402bf9,0xb40006d9,0xaa1903e0,0xaa1f03e1,0,0x35000600,
  0xaa1603e0,0,0xaa0003fa,0xf9002fff,0,0x7100041f,0x540000a0,0,
  0xaa0003fa,0xf9002fe0,0xb4000420,0xaa1903e0,0,0xf90033e0,0xaa1903e0,0,
  0xb4000300,0xaa1703e1,0xaa1803e2,0xd2800103,0xf94033e4,0xaa1a03e5,0x52840046,0,
  0xb4000200,0xaa0003fa,0x52800221,0,0xaa1a03e0,0xaa1603e1,0x9e6703e0,0x9e6703e1,
  0x9e6302e2,0x9e630303,0,0xaa1a03e0,0,0xaa1903e0,0xf9000280,0x2a1f03f5,
  0xf9402fe0,0xb4000040,0,0xaa1903e0,0xaa1f03e1,0,0x34000075,0xaa1903e0,
  0,0xaa1603e0,0,0x2a1503e0,0xa94153f3,0xa9425bf5,0xa94363f7,0xa9446bf9,
  0xa8c77bfd,0xd65f03c0,
  /* CVPixelBufferCreate wrapper for the ImageIO fallback only. CALayer
   * contents needs an IOSurface; request {IOSurfaceProperties: {}}.
   * Save width, height, format and out pointer while building attributes. */
  0xa9bc7bfd,0x910003fd,0xa9010be1,0xa90217e3,0xaa1f03e0,0xaa1f03e1,0xaa1f03e2,0xaa1f03e3,
  0xaa1f03e4,0xaa1f03e5,0,0xb4000380,0xf9001fe0,0,0,0xf9001be8,
  0xaa1f03e0,0x9100c3e1,0x9100e3e2,0xd2800023,0,0,0,0,
  /* Outer dictionary retains the inner one. Release the outer dictionary
   * after creation and return the original CoreVideo status. */
  0,0xf9001be0,0xf9401fe0,0,0xf9401be4,0xb4000144,0xaa1f03e0,0xa9410be1,
  0xa94217e3,0,0xb9003be0,0xf9401be0,0,0xb9403be0,0x14000002,0x128340a0,
  0xa8c47bfd,0xd65f03c0
 };
 /* Existing exports from the pinned cache set, or local helpers checked
  * above. Each thunk preserves LR and remains valid after the cache slides. */
 static const struct {uint32_t at; uint64_t dest;} calls[]={
  {0x1c,0x194be31b4}, /* VTCreateCGImageFromCVPixelBuffer */
  {0x38,0x1a010ea04}, /* saveImage:toURL:error: */
  {0x54,0x188571820}, /* CGImageRelease */
  {0x88,0x1a01134e4}, /* original pixel-buffer reader */
  {0xa0,0x1a010ec24}, /* newImageWithContentsOfURL:error: */
  {0xac,0x18858a534}, /* CGImageGetWidth */
  {0xb8,0x18856f99c}, /* CGImageGetHeight */
  {0x120,0x1a116b9c8}, /* CVPixelBufferLockBaseAddress */
  {0x12c,0x18857bf7c}, /* CGImageGetColorSpace */
  {0x138,0x18856f2b8}, /* CGColorSpaceGetModel */
  {0x144,0x1885a0210}, /* CGColorSpaceCreateDeviceRGB */
  {0x158,0x1a1171674}, /* CVPixelBufferGetBytesPerRow */
  {0x164,0x1a115b3f4}, /* CVPixelBufferGetBaseAddress */
  {0x184,0x1885a0334}, /* CGBitmapContextCreate */
  {0x194,0x18861c2b4}, /* CGContextSetBlendMode */
  {0x1b0,0x1885987ec}, /* CGContextDrawImage */
  {0x1b8,0x18856fa68}, /* CGContextRelease */
  {0x1d0,0x18856f540}, /* CGColorSpaceRelease */
  {0x1dc,0x1a115b544}, /* CVPixelBufferUnlockBaseAddress */
  {0x1e8,0x1a1158754}, /* CVPixelBufferRelease */
  {0x1f0,0x188571820}, /* CGImageRelease */
  {surface_at+0x28,0x181cef17c}, /* CFDictionaryCreate (empty IOSurface properties) */
  {surface_at+0x60,0x181cef17c}, /* CFDictionaryCreate (pixel buffer attributes) */
  {surface_at+0x6c,0x181ce5790}, /* CFRelease */
  {surface_at+0x84,0x1a116e908}, /* CVPixelBufferCreate */
  {surface_at+0x90,0x181ce5790}  /* CFRelease */
 };
 if(sizeof bridge!=surface_at+0xa8||bridge[surface_at/4]!=0xa9bc7bfdu||
    bridge[0x108/4]||old_read!=calls[3].dest)die("PhotosFormats layer bridge layout differs");
 size_t room=header_gap(im,sizeof bridge+12*N(calls));
 uint64_t wv=va(room),rv=wv+0x68;
 bridge[0x108/4]=branch(wv+0x108,wv+surface_at,-1)|0x80000000u;
 static const struct {uint32_t at,reg,indirect;uint64_t dest;} surface_data[]={
  {surface_at+0x34,8,1,0x1d769b8b0}, /* kCVPixelBufferIOSurfacePropertiesKey */
  {surface_at+0x50,4,0,0x1dfa26e68}, /* kCFTypeDictionaryKeyCallBacks */
  {surface_at+0x58,5,0,0x1dfa26ec8}  /* kCFTypeDictionaryValueCallBacks */
 };
 for(size_t i=0;i<N(surface_data);i++){
  uint32_t at=surface_data[i].at,reg=surface_data[i].reg,indirect=surface_data[i].indirect;
  uint64_t pc=wv+at,dst=surface_data[i].dest;
  int64_t delta=((int64_t)(dst&~UINT64_C(4095))-(int64_t)(pc&~UINT64_C(4095)))/4096;
  uint32_t low=(uint32_t)(dst&4095);
  if(delta<-(1<<20)||delta>=(1<<20)||bridge[at/4]||bridge[at/4+1]||(indirect&&low%8))
   die("PhotosFormats IOSurface data relocation differs");
  uint32_t v=(uint32_t)delta&0x1fffff;
  bridge[at/4]=0x90000000u|((v&3)<<29)|((v>>2)<<5)|reg;
  bridge[at/4+1]=(indirect?(0xf9400000u|((low/8)<<10)):(0x91000000u|(low<<10)))|(reg<<5)|reg;
 }
 for(size_t i=0;i<N(calls);i++){
  size_t gap=room+sizeof bridge+i*12;
  uint64_t cv=va(gap),dst=calls[i].dest;
  int64_t delta=((int64_t)(dst&~UINT64_C(4095))-(int64_t)(cv&~UINT64_C(4095)))/4096;
  if(delta<-(1<<20)||delta>=(1<<20)||bridge[calls[i].at/4])
   die("PhotosFormats bridge call relocation differs");
  uint32_t v=(uint32_t)delta&0x1fffff;
  bridge[calls[i].at/4]=branch(wv+calls[i].at,cv,-1)|0x80000000u;
  edit(gap,0x90000010u|((v&3)<<29)|((v>>2)<<5));
  edit(gap+4,0x91000210u|((uint32_t)(dst&4095)<<10));
  edit(gap+8,0xd61f0200u); /* br x16 */
 }
 for(size_t i=0;i<N(bridge);i++)edit(room+i*4,bridge[i]);
 edit(s,branch(va(s),wv,-1)|0x80000000u);
 edit(r,branch(va(r),rv,-1)|0x80000000u);
 photo_layer_name(im,UINT64_C(0x1a01a0913),"layer_%@.HEIC");
 photo_layer_name(im,UINT64_C(0x1a01a0921),"layer_%@_%ld.HEIC");
 printf("PhotosFormats: wallpaper layers -> PNG at +0x%zx; IOSurface-backed ImageIO reader fallback at +0x%zx\n",s,r);
}

static void nano(Image im){
 size_t found=0,hits=0;for(size_t p=im.code;p+N(nano_sig)*4<=im.code+im.code_size;p+=4){size_t j=0;
  for(;j<N(nano_sig);j++){if(j==10&&u32(p+j*4)==0x52800000u)continue;if((u32(p+j*4)&nano_sig[j].m)!=nano_sig[j].v)break;}
  if(j==N(nano_sig)){found=p;hits++;}}
 if(hits!=1)die("missing/ambiguous NanoRegistry capability check");
 if(u32(found+40)==0x52800000u){printf("NanoRegistry: existing watch-companion patch preserved\n");return;}
 edit(found+40,0x52800000);printf("NanoRegistry: watch-companion capability -> false at +0x%zx\n",found+40);
}
static void sleep_patch(Image im){size_t p=match(im,sleep_entry_sig,N(sleep_entry_sig),"Sleep TH1 entry"),t=match(im,sleep_target_sig,N(sleep_target_sig),"Sleep TH1 fallback");edit(p,branch(va(p),va(t),-1));printf("Sleep: TH1 entry +0x%zx -> fallback +0x%zx\n",p,t);}
static void radio(Image im){
 size_t ctx=match(im,radio_sig,N(radio_sig),"telephony unsupported model"),prof=match(im,j72s_sig,N(j72s_sig),"J72s profile");size_t site=ctx+48;
 if(target(u32(prof+8),va(prof+8))!=va(prof+20))die("J72s profile branch mismatch");
 uint64_t globals=page(u32(site),va(site));size_t refs[]={site+8,site+16,prof,prof+12,prof+24,prof+36};
 for(size_t i=0;i<N(refs);i++)if(page(u32(refs[i]),va(refs[i]))!=globals)die("radio profile globals mismatch");
 size_t cave=0,first=im.code;
 /* Header-to-first-section padding in this image only. Verify every section
  * starts after the candidate and does not occupy the 48-byte stub. */
 size_t p=im.header+32;
 for(uint32_t i=0;i<u32(im.header+16);i++){uint32_t cmd=u32(p),sz=u32(p+4);if(cmd==25&&!strncmp((char *)b+p+8,"__TEXT",16))for(uint32_t j=0;j<u32(p+64);j++){
  size_t q=p+72+(size_t)j*80;uint64_t a=u64(q+32),n=u64(q+40);if(n){size_t f=offset(a,(size_t)n);if(f<first)first=f;}
 }p+=sz;}
 for(size_t q=(im.header_end+3)&~(size_t)3;q+48<=first;q+=4){size_t j=0;for(;j<48;j++)if(b[q+j])break;if(j==48){cave=q;break;}}
 if(!cave)die("no zero telephony executable header padding");
 uint64_t cv=va(cave),sv=va(site),pv=va(prof);int64_t d=((int64_t)globals-(int64_t)((cv+40)&~UINT64_C(4095)))/4096;
 if(d<-(1<<20)||d>=(1<<20))die("radio ADRP range");uint32_t v=(uint32_t)d&0x1fffff;
 uint32_t stub[]={0xb94009c9,0x7100093f,0,0xd28008a9,0xf2c009c9,0xeb09017f,0,0xf2cea9c9,0xeb09017f,0,0,0};
 stub[2]=branch(cv+8,cv+40,1);stub[6]=branch(cv+24,pv,0);stub[9]=branch(cv+36,pv,0);
 stub[10]=0x90000009u|((v&3)<<29)|((v>>2)<<5);stub[11]=branch(cv+44,sv+4,-1);
 for(size_t i=0;i<N(stub);i++)edit(cave+i*4,stub[i]);edit(site,branch(sv,cv,-1));
 printf("Telephony: N69AP/N69uAP -> J72s product57/radio1/vendor1; fallback +0x%zx, stub +0x%zx\n",site,cave);
}

/* The model getter lives in .05. Resolve its model structure from a read-only
 * sibling cache; the .13 edit contains only a PC-relative reference to it. */
static uint64_t companion_model(const char *input){
 size_t n=strlen(input);if(n<3||strcmp(input+n-3,".13"))die("RFS input must end in .13 with a sibling .05 cache");
 char *path=malloc(n+1);if(!path)die("out of memory");memcpy(path,input,n+1);memcpy(path+n-2,"05",2);
 FILE *f=fopen(path,"rb");free(path);if(!f)die("RFS requires sibling .05 to resolve hardware-model storage");
 if(fseek(f,0,SEEK_END))die("cannot size companion");long sz=ftell(f);if(sz<512||fseek(f,0,SEEK_SET))die("invalid companion");
 unsigned char *cb=malloc((size_t)sz);if(!cb||fread(cb,1,(size_t)sz,f)!=(size_t)sz||fclose(f))die("cannot read companion");
 unsigned char *saved=b;size_t saved_length=length,saved_nm=nm;Mapping saved_maps[N(maps)];memcpy(saved_maps,maps,sizeof maps);
 b=cb;length=(size_t)sz;
 if(memcmp(b,"dyld_v1   arm64\0",16))die("invalid companion cache magic");
 uint32_t mo=u32(16),count=u32(20);if(!count||count>N(maps)||!fits(mo,(uint64_t)count*32))die("invalid companion mappings");nm=count;
 for(size_t i=0;i<nm;i++){size_t q=mo+i*32;maps[i]=(Mapping){u64(q),u64(q+8),u64(q+16),u32(q+28)};if(!fits(maps[i].off,maps[i].size)||maps[i].va>UINT64_MAX-maps[i].size)die("invalid companion extent");}
 Image im;if(!find_image("/usr/lib/libTelephonyUtilDynamic.dylib",&im))die("missing companion TelephonyUtil");
 const Word sig[]={
 {0xa9bf7bfd,~0u},{0x910003fd,~0u},{0x90000008,0x9f00001f},{0xf9401508,~0u},
 {0xb100051f,~0u},{0x54000001,0xff00001f},{0x90000000,0x9f00001f},{0x9100e000,~0u},
 {0xa8c17bfd,~0u},{0xd65f03c0,~0u}};
 size_t q=match(im,sig,N(sig),"hardware model getter");uint64_t pg=page(u32(q+8),va(q+8));
 if(page(u32(q+24),va(q+24))!=pg)die("model getter globals disagree");
 uint64_t model=pg+0x38;
 b=saved;length=saved_length;nm=saved_nm;memcpy(maps,saved_maps,sizeof maps);free(cb);return model;
}
static void rfs_location(Image im,const char *input){
 const Word sig[]={
 {0xa9be4ff4,~0u},{0xa9017bfd,~0u},{0x910043fd,~0u},{0xaa0003f3,~0u},{0x94000000,0xfc000000},
 {0x51000668,~0u},{0x7100091f,~0u},{0x54000003,0xff00001f},{0x7100127f,~0u},{0x54000001,0xff00001f},
 {0x7100841f,~0u},{0x54000000,0xff00001f},{0x7101101f,~0u},{0x54000000,0xff00001f},
 {0x7100e41f,~0u},{0x54000001,0xff00001f},{0x52a08200,~0u},{0x14000000,0xfc000000}};
 size_t q=match(im,sig,N(sig),"RFS USB location selector"),site=q+64;
 uint64_t resume=target(u32(site+4),va(site+4));
 if((va(q+52)+((u32(q+52)>>5)&0x7ffff)*4)!=va(site)||(va(q+44)+((u32(q+44)>>5)&0x7ffff)*4)!=va(q+100)||u32(q+100)!=0x52a06200)die("USB location branch topology mismatch");
 uint64_t model=companion_model(input);size_t first=im.code,p=im.header+32,cave=0;
 for(uint32_t i=0;i<u32(im.header+16);i++){uint32_t cmd=u32(p),sz=u32(p+4);if(cmd==25&&!strncmp((char *)b+p+8,"__TEXT",16))for(uint32_t j=0;j<u32(p+64);j++){size_t a=p+72+(size_t)j*80;if(u64(a+40)){size_t f=offset(u64(a+32),(size_t)u64(a+40));if(f<first)first=f;}}p+=sz;}
 for(size_t a=(im.header_end+3)&~(size_t)3;a+76<=first;a+=4){size_t j=0;for(;j<76;j++)if(b[a+j])break;if(j==76){cave=a;break;}}
 if(!cave)die("no executable header padding for RFS guard");
 uint64_t cv=va(cave);int64_t d=((int64_t)(model&~UINT64_C(4095))-(int64_t)((cv+8)&~UINT64_C(4095)))/4096;
 if(d<-(1<<20)||d>=(1<<20))die("model ADRP out of range");uint32_t v=(uint32_t)d&0x1fffff;
 uint32_t stub[]={0x7100e41f,0,0,0,0xb9400909,0x7100093f,0,0xf9400108,0xd28008a9,0xf2c009c9,0xeb09011f,0,0xf2cea9c9,0xeb09011f,0,0x52a06200,0,0x52a08200,0};
 stub[1]=branch(cv+4,cv+68,1);stub[2]=0x90000008|((v&3)<<29)|((v>>2)<<5);stub[3]=0x91000108|((uint32_t)(model&4095)<<10);
 stub[6]=branch(cv+24,cv+68,1);stub[11]=branch(cv+44,cv+60,0);stub[14]=branch(cv+56,cv+68,1);
 stub[16]=branch(cv+64,resume,-1);stub[18]=branch(cv+72,resume,-1);
 for(size_t i=0;i<N(stub);i++)edit(cave+i*4,stub[i]);edit(site,branch(va(site),cv,-1));
 printf("RFS: N69/N69u product57 USB location -> 0x03100000; other models retain 0x04100000.\n");
}
/* Validate Apple's existing ad-hoc SHA-256 CodeDirectory before modifying it.
 * This updates code-page hashes, not an Apple CMS signature or a trust cache. */
typedef struct {size_t cd,hash;uint32_t slots,limit,page;} Directory;
static Directory dirs[8];static size_t nd;
static void signature(int update){
 uint64_t start=u64(40),cap=u64(48);if(!fits(start,cap)||cap<12||be32((size_t)start)!=0xfade0cc0)die("missing embedded signature");
 uint32_t bytes=be32((size_t)start+4),count=be32((size_t)start+8);if(bytes>cap||bytes<12||count>(bytes-12)/8)die("invalid signature superblob");
 if(!update){
  for(uint32_t i=0;i<count;i++){
   size_t idx=(size_t)start+12+i*8;uint32_t kind=be32(idx),rel=be32(idx+4);if(rel>bytes||bytes-rel<8)die("bad signature blob offset");size_t cd=(size_t)start+rel;uint32_t magic=be32(cd),sz=be32(cd+4);if(sz<8||sz>bytes-rel)die("bad signature blob length");
   if(kind==0x10000){if(magic!=0xfade0b01||sz!=8)die("CMS-signed cache unsupported: cannot forge Apple signature");continue;}
   if(magic!=0xfade0c02)continue;
   if(nd==N(dirs)||sz<88||be32(cd+8)!=0x20400||!(be32(cd+12)&2)||b[cd+36]!=32||b[cd+37]!=2||b[cd+39]>20)die("unsupported CodeDirectory (requires ad-hoc SHA256 v20400)");
   uint32_t hash=be32(cd+16),slots=be32(cd+28),limit=be32(cd+32),pg=1u<<b[cd+39];
   if(be32(cd+44)||u64(cd+56)||hash>sz||(uint64_t)slots*32>sz-hash||limit>start||slots!=((uint64_t)limit+pg-1)/pg)die("unsupported code-signing geometry");
   dirs[nd++]=(Directory){cd,cd+hash,slots,limit,pg};
  }
  if(!nd)die("no SHA256 CodeDirectory");
 }
 for(size_t j=0;j<nd;j++){
  Directory *d=&dirs[j];for(uint32_t i=0;i<d->slots;i++){
   size_t p=(size_t)i*d->page,n=d->limit-p;if(n>d->page)n=d->page;unsigned char digest[32];CC_SHA256(b+p,(CC_LONG)n,digest);
   if(update)memcpy(b+d->hash+(size_t)i*32,digest,32);
   else if(memcmp(b+d->hash+(size_t)i*32,digest,32))die("input code-page hash mismatch (modified or corrupted cache)");
  }
 }
}
static void save(const char *path){size_t n=strlen(path);if(n>SIZE_MAX-16)die("path too long");char *tmp=malloc(n+16);if(!tmp)die("out of memory");snprintf(tmp,n+16,"%s.tmp.XXXXXX",path);int fd=mkstemp(tmp);if(fd<0){perror("dscpatch: temporary output");exit(1);}int err=0;size_t p=0;while(p<length){size_t z=length-p;if(z>1048576)z=1048576;ssize_t w=write(fd,b+p,z);if(w<0&&errno==EINTR)continue;if(w<=0){err=errno?errno:EIO;break;}p+=(size_t)w;}if(!err&&fsync(fd))err=errno;if(close(fd)&&!err)err=errno;if(!err&&link(tmp,path))err=errno;unlink(tmp);free(tmp);if(err){errno=err;perror("dscpatch: publish output (existing paths refused)");exit(1);}}
int main(int argc,char **argv){
 if(argc!=3){fprintf(stderr,"usage: %s [input cache/subcache] [output patched]\n",argv[0]);return 2;}
 FILE *f=fopen(argv[1],"rb");if(!f){perror("dscpatch: input");return 1;}struct stat st;if(fstat(fileno(f),&st)||!S_ISREG(st.st_mode)||st.st_size<512||(uintmax_t)st.st_size>SIZE_MAX)die("invalid input");length=(size_t)st.st_size;b=malloc(length);if(!b)die("out of memory");if(fread(b,1,length,f)!=length)die("read failed");if(fclose(f))die("close failed");
 if(memcmp(b,"dyld_v1   arm64\0",16))die("expected plain ARM64 dyld shared cache/subcache");uint32_t mo=u32(16),count=u32(20);if(!count||count>N(maps)||!fits(mo,(uint64_t)count*32))die("invalid mapping table");nm=count;
 for(size_t i=0;i<nm;i++){size_t p=mo+i*32;maps[i]=(Mapping){u64(p),u64(p+8),u64(p+16),u32(p+28)};if(!fits(maps[i].off,maps[i].size)||maps[i].va>UINT64_MAX-maps[i].size)die("invalid mapping extent");for(size_t j=0;j<i;j++)if(maps[i].size&&maps[j].size&&maps[i].off<maps[j].off+maps[j].size&&maps[j].off<maps[i].off+maps[i].size)die("overlapping mappings");}
 signature(0);Image im;unsigned targets=0;
 if(find_image("/System/Library/PrivateFrameworks/NanoRegistry.framework/NanoRegistry",&im)){nano(im);targets++;}
 if(find_image("/System/Library/PrivateFrameworks/PhotosFormats.framework/PhotosFormats",&im)){photo_proxy(im,argv[1]);photo_layers(im);targets++;}
 if(find_image("/System/Library/PrivateFrameworks/AVFCapture.framework/AVFCapture",&im)){camera(im);targets++;}
 if(find_image("/System/Library/PrivateFrameworks/Sleep.framework/Sleep",&im)){sleep_patch(im);targets++;}
 if(find_image("/usr/lib/libTelephonyUtilDynamic.dylib",&im)){radio(im);targets++;}
 if(find_image("/usr/lib/libBasebandCapabilities.dylib",&im)){rfs_location(im,argv[1]);targets++;}
 if(!targets||!ne)die("no supported target images in this cache/subcache; no output");
 for(size_t i=0;i<ne;i++){for(size_t j=0;j<nd;j++)if(edits[i].at>dirs[j].limit||4>dirs[j].limit-edits[i].at)die("patch outside signed code range");put32(edits[i].at,edits[i].word);}
 signature(1);save(argv[2]);free(b);printf("Wrote %s (%zu bytes, %u target(s), %zu instruction writes); SHA256 code-page hashes refreshed. Hardware testing pending.\n",argv[2],length,targets,ne);return 0;
}
