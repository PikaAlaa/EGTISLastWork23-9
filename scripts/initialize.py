"""Initialize only the configured local project database; never connect to a previous checkout implicitly."""
import argparse,json,re,secrets,subprocess,sys,os
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def ensure_env_secrets(env):
    """Add missing local secrets to an existing .env; never replace a value that is already set."""
    content=env.read_text(encoding='utf-8')
    if 'ETIS_DB_PASSWORD=' not in content:
        content=content.rstrip('\n')+'\nETIS_DB_PASSWORD='+secrets.token_hex(24)+'\n'
    # Host engine pseudonyms (docs/design/host-engine-v1.md section 6.4): dedicated HMAC key, 32 random bytes.
    key=re.search(r'^ETIS_HOST_PSEUDONYM_KEY=(.*)$',content,re.M)
    if key is None:
        content=content.rstrip('\n')+'\nETIS_HOST_PSEUDONYM_KEY='+secrets.token_hex(32)+'\n'
    elif not key.group(1).strip():
        content=content[:key.start()]+'ETIS_HOST_PSEUDONYM_KEY='+secrets.token_hex(32)+content[key.end():]
    env.write_text(content,encoding='utf-8')
def initialize(seed=False):
    env=ROOT/'.env'
    if not env.exists() and not os.getenv('ETIS_API_KEY'):
        template=(ROOT/'.env.example').read_text(encoding='utf-8')
        env.write_text(template.replace('ETIS_API_KEY=','ETIS_API_KEY='+secrets.token_urlsafe(32),1),encoding='utf-8')
    if env.exists():ensure_env_secrets(env)
    subprocess.run([sys.executable,'-m','alembic','upgrade','head'],cwd=ROOT,check=True)
    sys.path.insert(0,str(ROOT/'backend'))
    from app.core.database import SessionLocal
    from app.services.registry import populate_registry
    from app.services.findings import seed_correlation_stoplist
    with SessionLocal() as db:populate_registry(db)
    with SessionLocal() as db:seed_correlation_stoplist(db)
    from app.services.attack import load_catalogue
    # Local pinned files only (data/scripts/fetch_attack.py); absent files leave the catalogue not installed.
    with SessionLocal() as db:attack=load_catalogue(db)
    if seed:
        subprocess.run([sys.executable,'data/scripts/seed_database.py','--mode','archive'],cwd=ROOT,check=True)
    print(json.dumps({'initialized':True,'database':'project-local SQLite unless DATABASE_URL explicitly configured','key':'stored in ignored .env; never printed','attack_catalogue':attack}))
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--seed-archive',action='store_true');initialize(p.parse_args().seed_archive)
