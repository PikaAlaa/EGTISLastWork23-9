"""Initialize only the configured local project database; never connect to a previous checkout implicitly."""
import argparse,json,secrets,subprocess,sys,os
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def initialize(seed=False):
    env=ROOT/'.env'
    if not env.exists() and not os.getenv('ETIS_API_KEY'):
        template=(ROOT/'.env.example').read_text(encoding='utf-8')
        env.write_text(template.replace('ETIS_API_KEY=','ETIS_API_KEY='+secrets.token_urlsafe(32),1),encoding='utf-8')
    if env.exists():
        content=env.read_text(encoding='utf-8')
        if 'ETIS_DB_PASSWORD=' not in content:
            env.write_text(content+'\nETIS_DB_PASSWORD='+secrets.token_hex(24)+'\n',encoding='utf-8')
    subprocess.run([sys.executable,'-m','alembic','upgrade','head'],cwd=ROOT,check=True)
    sys.path.insert(0,str(ROOT/'backend'))
    from app.core.database import SessionLocal
    from app.services.registry import populate_registry
    with SessionLocal() as db:populate_registry(db)
    if seed:
        subprocess.run([sys.executable,'data/scripts/seed_database.py','--mode','archive'],cwd=ROOT,check=True)
    print(json.dumps({'initialized':True,'database':'project-local SQLite unless DATABASE_URL explicitly configured','key':'stored in ignored .env; never printed'}))
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--seed-archive',action='store_true');initialize(p.parse_args().seed_archive)
