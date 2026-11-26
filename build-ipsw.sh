#!/bin/bash

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "Enter your sudo password when prompted to"
sudo -v || exit 1

rm -rf "work"
rm -rf "tmp1"
rm -rf "tmp2"
rm -rf "tmp3"
set -euo pipefail

echo "iPhone SE 1 IPSW builder for iOS 16.1"

# Bootstrap the tools used by this builder.
setup_tools() (
    if ! command -v python3 >/dev/null 2>&1; then
        echo "python3 is required for the audio driver port (patchsrc/audioport). Install it, then re-run." >&2
        exit 1
    fi
    mkdir -p bin
    if [[ ! -x bin/iBootpatch2 ]]; then
        git clone https://github.com/crystall1nedev/ipad6-ipados18 -b ssv-patch
        cd ipad6-ipados18
        make
        cp -v iBootpatch2 ../bin/iBootpatch2
        cd ..
        rm -rf "ipad6-ipados18"
    fi

    local scratch arch tool source
    scratch=$(mktemp -d "${TMPDIR:-/tmp}/se1-tools.XXXXXX")
    trap 'rm -rf -- "$scratch"' EXIT

    download_tool() {
        local name="$1" url="$2"
        [[ ! -x "bin/$name" ]] || return 0
        curl -fL --retry 3 -o "$scratch/$name" "$url"
        install -m 0755 "$scratch/$name" "bin/$name"
    }

    arch=$(uname -m)
    download_tool img4 https://github.com/LukeZGD/Legacy-iOS-Kit/raw/refs/heads/main/bin/macos/img4
    download_tool ldid "https://github.com/ProcursusTeam/ldid/releases/download/v2.1.5-procursus7/ldid_macosx_$arch"
    download_tool Kernel64Patcher https://github.com/edwin170/downr1n/raw/refs/heads/main/binaries/Darwin/Kernel64Patcher
    download_tool KPlooshFinder https://github.com/LukeZGD/Legacy-iOS-Kit/raw/refs/heads/main/bin/macos/KPlooshFinder

    if [[ ! -x bin/kerneldiff2 ]]; then
        curl -fL --retry 3 -o "$scratch/kerneldiff.c" https://gist.githubusercontent.com/pwnerblu/46021f9d633d579bf9e950f66679e37c/raw/93fc81591cfb4b04b5fab13144f68d877a42769d/kerneldiff.c
        gcc "$scratch/kerneldiff.c" -o "$scratch/kerneldiff2"
        install -m 0755 "$scratch/kerneldiff2" bin/kerneldiff2
    fi
    if [[ ! -x bin/apfs-tool ]]; then
        git clone https://github.com/LukeZGD/libdmg-apfs "$scratch/libdmg-apfs"
        make -C "$scratch/libdmg-apfs"
        install -m 0755 "$scratch/libdmg-apfs/build/apfs-tool" bin/apfs-tool
    fi
    if [[ ! -x bin/restored_external64_patcher ]]; then
        git clone --recursive https://github.com/iSuns9/restored_external64patcher "$scratch/restored_external64patcher"
        make -C "$scratch/restored_external64patcher"
        install -m 0755 "$scratch/restored_external64patcher/restored_external64_patcher" bin/restored_external64_patcher
    fi

    for source in patchsrc/*.c; do
        tool=${source##*/}
        tool=${tool%.c}
        case "$tool" in
            sepfix) continue ;;
            backboardhax) tool=backboarddpatcher ;;
        esac
        gcc -O2 "$source" -o "$scratch/$tool"
        install -m 0755 "$scratch/$tool" "bin/$tool"
    done
)

setup_tools

if [[ ! -f iPhone_4.7_P3_16.1_20B82_Restore.ipsw ]]; then
	echo "iPhone 8 iOS 16.1 IPSW does not exist in the script directory!"
	exit 1
elif [[ ! -f iPad_64bit_TouchID_ASTC_16.1_20B82_Restore.ipsw ]]; then
	echo "iPad 5 iOS 16.1 IPSW does not exist in the script directory!"
	exit 1
elif [[ ! -f iPhone_4.0_64bit_15.8.8_19H422_Restore.ipsw ]]; then
	echo "iPhone SE iOS 15.8.8 IPSW does not exist in the script directory!"
	exit 1
fi

SE_IPSW="iPhone_4.0_64bit_15.8.8_19H422_Restore.ipsw"
IPAD_IPSW="iPad_64bit_TouchID_ASTC_16.1_20B82_Restore.ipsw"
IPHONE_IPSW="iPhone_4.7_P3_16.1_20B82_Restore.ipsw"

if [[ -f iPhone_4.0_64bit_16.1_20B82_Restore.ipsw ]]; then
	echo "Custom iPhone SE iOS 16.1 IPSW already exists"
	echo "Tether restore this IPSW with turdus merula: https://sep.lol"
	exit 0
else
	echo "Custom restore IPSW does not exist, creating a new one"
fi

unzip $SE_IPSW -d tmp1
unzip $IPHONE_IPSW -d tmp2
rm -rf tmp2/078-65022-105.dmg
mkdir -p work
curl -L -o work/template.dmg https://github.com/pwnerblu/extra-resources-ipad1/releases/download/1.0/template.dmg
hdiutil resize -size 11500m work/template.dmg
hdiutil attach tmp1/098-68807-067.dmg -mountpoint rootfs15
hdiutil attach tmp2/078-65562-105.dmg -mountpoint rootfs16base
sudo hdiutil attach work/template.dmg -mountpoint rootfs16
sudo diskutil enableOwnership rootfs16
sudo mount -urw rootfs16
sudo rsync -a rootfs16base/ rootfs16
hdiutil detach rootfs16base
rm -rf tmp2/078-65562-105.dmg
sudo find rootfs15 -iregex '.*n69.*' -type f -exec /bin/sh -c 'dirname="$(echo "{}" | sed -E '\''s|^rootfs15(/.+)/.+$|\1|'\'')"; filename="$(echo "{}" | sed -E '\''s|rootfs15/.+/(.+)$|\1|'\'')"; mkdir -p "rootfs16/${dirname}"; cp -anv "{}" "rootfs16/${dirname}/${filename}";' \;
sudo cp -av rootfs15/usr/share/firmware/wifi/* rootfs16/System/Library/DriverExtensions/com.apple.DriverKit-AppleBCMWLAN.dext/Firmware
hdiutil detach rootfs15
rm -rf tmp1/098-68807-067.dmg

# Replace only the poster provider override; preserve the SE's other jetsam limits.
jetsam_dir="rootfs16/System/Library/LaunchDaemons"
poster_provider_key='Version4.Extension.Override.com\.apple\.posterkit\.provider'
poster_provider_limits=$(plutil -extract "$poster_provider_key" xml1 -expect dictionary -o - \
    "$jetsam_dir/com.apple.jetsamproperties.D20.plist")
for model in N69 N69u; do
    sudo plutil -replace "$poster_provider_key" -xml "$poster_provider_limits" \
        "$jetsam_dir/com.apple.jetsamproperties.$model.plist"
done

# Change the screen-class filter without renaming bundles or animation assets.
wallpaper_dir="rootfs16/Library/Wallpaper/Collections"
sudo plutil -replace logicalScreenClass -string '320w-568h@2x~iphone' \
    "$wallpaper_dir/iOS_16~iphone.wallpaperCollection/Wallpapers/7400.WWDC_2022-375w-667h@2x~iphone.wallpaper/Wallpaper.plist" \
    "$wallpaper_dir/Clownfish~iphone.wallpaperCollection/Wallpapers/7420.Clownfish-375w-667h@2x~iphone.wallpaper/Wallpaper.plist"

./bin/ldid -e rootfs16/System/Library/DriverExtensions/com.apple.DriverKit-AppleBCMWLAN.dext/com.apple.DriverKit-AppleBCMWLAN > work/ents.plist
./bin/wlanhax rootfs16/System/Library/DriverExtensions/com.apple.DriverKit-AppleBCMWLAN.dext/com.apple.DriverKit-AppleBCMWLAN work/dext.patch
./bin/ldid -Swork/ents.plist work/dext.patch
sudo cp -v work/dext.patch rootfs16/System/Library/DriverExtensions/com.apple.DriverKit-AppleBCMWLAN.dext/com.apple.DriverKit-AppleBCMWLAN
sudo chmod 755 rootfs16/System/Library/DriverExtensions/com.apple.DriverKit-AppleBCMWLAN.dext/com.apple.DriverKit-AppleBCMWLAN
sudo chown root:wheel rootfs16/System/Library/DriverExtensions/com.apple.DriverKit-AppleBCMWLAN.dext/com.apple.DriverKit-AppleBCMWLAN
# Backboardd patches
./bin/backboarddpatcher rootfs16/usr/libexec/backboardd work/backboardd.patch
./bin/ldid -e rootfs16/usr/libexec/backboardd > work/ents.plist
./bin/ldid -Swork/ents.plist work/backboardd.patch
sudo cp -v work/backboardd.patch rootfs16/usr/libexec/backboardd
sudo chmod 755 rootfs16/usr/libexec/backboardd
sudo chown root:wheel rootfs16/usr/libexec/backboardd
unzip $IPAD_IPSW -d tmp3
hdiutil attach tmp3/078-65701-105.dmg -mountpoint rootfs16ipad
hdiutil attach tmp3/078-64804-105.dmg -mountpoint cryptexOS
hdiutil attach tmp3/078-64825-107.dmg -mountpoint cryptexApp
# Hm alright. Let's prep some kernel patching here.
./bin/img4 -i tmp3/kernelcache.release.ipad6f -o work/kernel.raw
./bin/img4 -i tmp1/kernelcache.release.iphone8b -o work/kernel-SE.raw
./bin/pmuhax work/kernel.raw work/kernel.patch
./bin/kextport work/kernel.patch work/kernel-SE.raw work/kernel.patch2
python3 patchsrc/audioport.py work/kernel.patch2 work/kernel-SE.raw work/kernel.patch2a
./bin/mthax work/kernel.patch2a work/kernel.patch3
./bin/Kernel64Patcher work/kernel.patch3 work/kernel.patch4 -e -h
./bin/KPlooshFinder work/kernel.patch4 work/kernel.patch5
./bin/kerneldiff2 work/kernel.raw work/kernel.patch4 work/kernel.diff
./bin/kerneldiff2 work/kernel.raw work/kernel.patch5 work/kernel.diff2
./bin/img4 -i tmp3/kernelcache.release.ipad6f -o tmp1/kernelcache.release.iphone8b -T krnl -P work/kernel.diff
./bin/img4 -i tmp3/kernelcache.release.ipad6f -o tmp1/kernelcache.release.iphone8c -T krnl -P work/kernel.diff2
# Done with that. Can now prep Cryptex
sudo rm -rf rootfs16/System/Cryptexes/OS
sudo rm -rf rootfs16/System/Cryptexes/App
sudo mkdir -p rootfs16/System/Cryptexes/OS
sudo mkdir -p rootfs16/System/Cryptexes/App
sudo rsync -av cryptexOS/ rootfs16/System/Cryptexes/OS
sudo rsync -av cryptexApp/ rootfs16/System/Cryptexes/App
sudo mv -v rootfs16/System/Cryptexes/OS/System/Library/Caches/com.apple.dyld rootfs16/System/Library/Caches
hdiutil detach cryptexOS
hdiutil detach cryptexApp
# Now, copy the H6ISP and fix Graphics.
sudo cp -av rootfs16ipad/System/Library/PrivateFrameworks/H6ISPServices.framework rootfs16/System/Library/PrivateFrameworks
sudo cp -av rootfs16ipad/System/Library/Extensions/AGXMetalA9.bundle rootfs16/System/Library/Extensions

for model in N69 N69u; do
    camera_config="rootfs16/System/Library/PrivateFrameworks/CMCapture.framework/$model"
    camera_setup="$camera_config/CameraSetup.plist"
    vis_config=TuningParameters.Common.VideoStabilization

    sudo plutil -replace AVCaptureDevices.0.stillImageNoiseReductionAndFusionScheme \
        -integer 1 "$camera_config/AVCaptureSession.plist" || exit 1

    for key in TuningParameters.Common "$vis_config"; do
        if ! plutil -extract "$key" raw -expect dictionary -o /dev/null "$camera_setup" >/dev/null 2>&1; then
            sudo plutil -insert "$key" -dictionary "$camera_setup" || exit 1
        fi
    done
    sudo plutil -replace "$vis_config.Version" -integer 2 "$camera_setup" || exit 1
done

hdiutil detach rootfs16ipad
rm -rf tmp2
rm -rf tmp3/078-65701-105.dmg
rm -rf tmp3/078-64804-105.dmg
rm -rf tmp3/078-64825-107.dmg
# Patch DSC. Needed for multiple functionality fixes
./bin/dscpatch rootfs16/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64.05 work/dyld05
sudo mv -v work/dyld05 rootfs16/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64.05
./bin/dscpatch rootfs16/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64.09 work/dyld09
sudo mv -v work/dyld09 rootfs16/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64.09
./bin/dscpatch rootfs16/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64.11 work/dyld11
sudo mv -v work/dyld11 rootfs16/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64.11
./bin/dscpatch rootfs16/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64.13 work/dyld13
sudo mv -v work/dyld13 rootfs16/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64.13
sudo chown root:wheel rootfs16/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64*
sudo chmod 755 rootfs16/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64*
# All done with the iPad stuff.
hdiutil detach rootfs16
hdiutil convert -format ULFO -o tmp1/098-68807-067.dmg work/template.dmg
rm -rf work/template.dmg
asr imagescan --source tmp1/098-68807-067.dmg
# Patch restore ramdisk and prep restores, copy iPad 5 SEPfw
cp -v tmp3/Firmware/all_flash/sep-firmware.j72t.RELEASE.im4p tmp1/Firmware/all_flash/sep-firmware.n69.RELEASE.im4p
cp -v tmp3/Firmware/all_flash/sep-firmware.j72s.RELEASE.im4p tmp1/Firmware/all_flash/sep-firmware.n69u.RELEASE.im4p
./bin/img4 -i tmp3/078-64668-109.dmg -o work/ramdisk.raw
rm -rf tmp3
# bbupdate fix
./bin/apfs-tool work/ramdisk.raw extract usr/lib/libTelephonyUtilDynamic.dylib work/libTelephonyUtilDynamic.dylib
./bin/bbupdaterpatch work/libTelephonyUtilDynamic.dylib work/libTelephonyUtilDynamic.patch
./bin/ldid -S work/libTelephonyUtilDynamic.patch
./bin/apfs-tool work/ramdisk.raw rm usr/lib/libTelephonyUtilDynamic.dylib 
./bin/apfs-tool work/ramdisk.raw add work/libTelephonyUtilDynamic.patch usr/lib/libTelephonyUtilDynamic.dylib 
./bin/apfs-tool work/ramdisk.raw chmod 755 usr/lib/libTelephonyUtilDynamic.dylib 
# restored_external
./bin/apfs-tool work/ramdisk.raw extract usr/local/bin/restored_external work/restored_external
./bin/restored_external64_patcher work/restored_external work/restored_patch
./bin/ldid -e work/restored_external > work/ents.plist
./bin/ldid -Swork/ents.plist work/restored_patch
./bin/apfs-tool work/ramdisk.raw rm usr/local/bin/restored_external
./bin/apfs-tool work/ramdisk.raw add work/restored_patch usr/local/bin/restored_external
./bin/apfs-tool work/ramdisk.raw chmod 755 usr/local/bin/restored_external
./bin/img4 -i work/ramdisk.raw -o tmp1/098-68700-067.dmg -A -T rdsk
# Finish up!
./bin/img4 -i tmp1/Firmware/all_flash/iBoot.n69.RELEASE.im4p -o work/iBoot.dec -k ad86b28172e561c8694035de80e93ba2d4fa9cc3dcb390afeaa991dcb4310103ddfe49b69d5edad2d3989585d73c74b2
./bin/img4 -i tmp1/Firmware/all_flash/iBoot.n69u.RELEASE.im4p -o work/iBoot-n69u.dec -k b35d235c6677fb5553c1eca51207a8be6b3930cddbf2296a488cae37e5f00bfefaed17eb241114d5fed913267ea12a29
./bin/iBootpatch2 -R -i work/iBoot.dec -o work/iBoot.patch
./bin/iBootpatch2 -R -i work/iBoot-n69u.dec -o work/iBoot-n69u.patch
./bin/img4 -i work/iBoot.patch -o tmp1/Firmware/all_flash/iBoot.n69.RELEASE.im4p -A -T ibot
./bin/img4 -i work/iBoot-n69u.patch -o tmp1/Firmware/all_flash/iBoot.n69u.RELEASE.im4p -A -T ibot
rm -rf work
sudo plutil -replace ProductBuildVersion -string 20B82 tmp1/BuildManifest.plist
sudo plutil -replace ProductVersion -string 16.1 tmp1/BuildManifest.plist
sudo plutil -replace BuildIdentities.0.Manifest.KernelCache.Info.Path -string kernelcache.release.iphone8c tmp1/BuildManifest.plist
sudo plutil -replace BuildIdentities.1.Manifest.KernelCache.Info.Path -string kernelcache.release.iphone8c tmp1/BuildManifest.plist
cd tmp1 
zip -0 -r ../iPhone_4.0_64bit_16.1_20B82_Restore.ipsw *
cd ..
rm -rf "tmp1"
echo "Restore bundle is created. You can restore it via turdus merula (https://sep.lol)"
exit 0
