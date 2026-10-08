import type { Verdict } from '../api/types';
export const VERDICT_STYLE: Record<Verdict, {bg: string; accent: string; chipColor: 'success'|'warning'|'error'|'default'}> = {
 LOW: {bg:'#eafbf1',accent:'#24663e',chipColor:'success'},
 MEDIUM: {bg:'#fdf3e3',accent:'#805300',chipColor:'warning'},
 HIGH: {bg:'#fdecea',accent:'#a52b20',chipColor:'error'},
 INCOMPLETE: {bg:'#edf1f6',accent:'#37475e',chipColor:'default'},
};
