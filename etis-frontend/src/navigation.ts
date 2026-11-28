import RadarIcon from '@mui/icons-material/Radar';
import DynamicFeedIcon from '@mui/icons-material/DynamicFeed';
import InsightsOutlinedIcon from '@mui/icons-material/InsightsOutlined';
import ReportOutlinedIcon from '@mui/icons-material/ReportOutlined';
import FingerprintIcon from '@mui/icons-material/Fingerprint';
import LanIcon from '@mui/icons-material/Lan';
import DevicesOtherOutlinedIcon from '@mui/icons-material/DevicesOtherOutlined';
import ManageSearchIcon from '@mui/icons-material/ManageSearch';
import AccountTreeOutlinedIcon from '@mui/icons-material/AccountTreeOutlined';

export const NAV = [
  ['scan', RadarIcon], ['threats', DynamicFeedIcon], ['stats', InsightsOutlinedIcon],
  ['incidents', ReportOutlinedIcon], ['files', FingerprintIcon], ['network', LanIcon], ['devices', DevicesOtherOutlinedIcon],
  ['indicators', ManageSearchIcon], ['attack', AccountTreeOutlinedIcon],
] as const;

export type PageKey = (typeof NAV)[number][0];

export function pageFromPath(): PageKey {
  return NAV.find(([key]) => key === location.pathname.slice(1))?.[0] ?? 'scan';
}
