import glob
import os
import shutil

import git

tests_dir = os.path.dirname(os.path.abspath(__file__))
repo_url = "https://github.com/FFRI/FEXRD-test-files.git"
dst_dir = os.path.join(tests_dir, "test-files")

git.Repo.clone_from(repo_url, dst_dir)

for d in glob.glob(os.path.join(dst_dir, "test_*")):
    copied_dir = os.path.join(tests_dir, os.path.basename(d))
    if os.path.exists(copied_dir):
        shutil.rmtree(copied_dir)
    shutil.move(d, copied_dir)

shutil.rmtree(dst_dir)
