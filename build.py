import os
import shutil
import subprocess
import sys
from pathlib import Path

def main():
    print("🚀 Starting Official HalalGPP Builder (Nuitka powered)...")
    
    # Define paths
    project_root = Path(__file__).parent
    dist_dir = project_root / "dist"
    entry_point = project_root / "entry_build_temp.py"
    output_exe_name = "HalalGPP.exe"
    
    # 1. Create a temporary entry point for the build
    print("📝 Creating temporary entry point...")
    with open(entry_point, "w") as f:
        f.write("from halal_gpp.app import main\n")
        f.write("if __name__ == '__main__':\n")
        f.write("    main()\n")

    # 2. Construct Nuitka command
    # We use sys.executable to ensure we use the same python interpreter (likely the uv venv)
    cmd = [
        sys.executable, "-m", "nuitka",
        "--onefile",
        "--enable-plugin=pyside6",
        "--windows-disable-console",
        f"--output-filename={output_exe_name}",
        "--assume-yes-for-downloads",
        "--include-package=halal_gpp",
        # Clean up build directory automatically
        "--remove-output", 
        str(entry_point)
    ]

    print(f"🔨 Running build command: {' '.join(cmd)}")
    print("⏳ This might take a minute or two. Go grab a coffee/tea...")

    try:
        subprocess.check_call(cmd, cwd=project_root)
        print("✅ Build successful!")
        
        # Move the resulting EXE to a clean 'dist' folder if desired, or leave in root
        # For now, let's leave it in root as per previous user request, but maybe log it.
        exe_path = project_root / output_exe_name
        if exe_path.exists():
            print(f"🎉 Executable created at: {exe_path}")
            
    except subprocess.CalledProcessError as e:
        print(f"❌ Build failed with exit code {e.returncode}")
        sys.exit(e.returncode)
    finally:
        # 3. Cleanup
        print("🧹 Cleaning up temporary files...")
        if entry_point.exists():
            entry_point.unlink()
        
        # Nuitka might leave some folders if --remove-output didn't catch everything or if it failed
        # The patterns are typically:
        # entry_build_temp.build/
        # entry_build_temp.onefile-build/
        # entry_build_temp.dist/
        base_name = entry_point.stem
        for suffix in [".build", ".dist", ".onefile-build"]:
            d = project_root / (base_name + suffix)
            if d.exists():
                try:
                    shutil.rmtree(d)
                    print(f"   Removed {d.name}")
                except Exception as e:
                    print(f"   Warning: Could not remove {d.name}: {e}")

if __name__ == "__main__":
    main()
