# Complete Prompt for Figma Make: SF Recon Engine - Standalone Application

Copy and paste this entire prompt into Figma Make to generate the complete SF Recon Engine application.

---

ast month"
   - ChangeType: increase
   - Icon: Package (blue gradient circle)

2. **Critical Findings**
   - Value: "23"
   - Change: "-8% from last week"
   - ChangeType: decrease
   - Icon: AlertTriangle (red gradient circle)

3. **Risk Score**
   - Value: "7.2/10"
   - Change: "+0.3 from last scan"
   - ChangeType: increase
   - Icon: Shield (orange gradient circle)

4. **Last Scan**
   - Value: "2 hours ago"
   - Change: "Next: In 4 hours"
   - ChangeType: neutral (just show text, no arrow)
   - Icon: Clock (green gradient circle)

**Section 2 - Two Column Charts**:

**Left Chart - Risk Score Trend (60% width)**:
- Card with white background, rounded-2xl
- Title: "Risk Score Trend"
- Subtitle: "Last 30 days"
- Line chart using Recharts
- Data points (30 days): Values ranging 6.8 to 7.5
- Blue line color
- Gradient fill under line
- Grid lines
- Tooltip on hover

Mock data structure:
```javascript
[
  { date: 'Jan 1', score: 6.8 },
  { date: 'Jan 5', score: 7.0 },
  { date: 'Jan 10', score: 7.2 },
  { date: 'Jan 15', score: 7.1 },
  { date: 'Jan 20', score: 7.3 },
  { date: 'Jan 25', score: 7.5 },
  { date: 'Jan 30', score: 7.2 }
]
```

**Right Chart - Finding Types (40% width)**:
- Card with white background, rounded-2xl
- Title: "Finding Distribution"
- Subtitle: "By severity"
- Vertical bar chart or pie chart
- Categories:
  - Critical: 23 (red-500)
  - High: 47 (orange-500)
  - Medium: 89 (yellow-500)
  - Low: 156 (green-500)

**Section 3 - Recent Scans Table**:
- Card with white background, rounded-2xl, p-6
- Title: "Recent Scans"
- Subtitle: "Last 10 scan activities"

Table columns:
1. Scan Target (bold text)
2. Type (badge: "Full Scan" blue, "Quick Scan" gray)
3. Status (badge: "Completed" green, "In Progress" blue, "Failed" red)
4. Findings (number with color)
5. Date (gray text)
6. Actions (View button - blue text with ChevronRight icon)

Mock data (5 rows):
```javascript
[
  {
    target: 'acme-corp.com',
    type: 'Full Scan',
    status: 'Completed',
    findings: 23,
    date: '2 hours ago'
  },
  {
    target: '203.0.113.0/24',
    type: 'Network Scan',
    status: 'Completed',
    findings: 15,
    date: '5 hours ago'
  },
  {
    target: 'app.acme-corp.com',
    type: 'Quick Scan',
    status: 'In Progress',
    findings: 8,
    date: '1 hour ago'
  },
  {
    target: 'api.acme-corp.com',
    type: 'Full Scan',
    status: 'Completed',
    findings: 31,
    date: '1 day ago'
  },
  {
    target: '*.acme-corp.com',
    type: 'Subdomain Scan',
    status: 'Failed',
    findings: 0,
    date: '2 days ago'
  }
]
```

---

### PAGE 2: ASSET INVENTORY (/src/app/pages/recon/AssetInventory.tsx)

**Header**:
- Title: "Asset Inventory"
- Subtitle: "Complete view of discovered assets"
- Right side: Search bar (Search icon, placeholder "Search assets...")
- Export button (Download icon)

**Filters Section**:
- Horizontal row of filter buttons
- "All Assets" (active by default - blue background)
- "Domains" (Package icon)
- "IP Addresses" (Network icon)
- "Cloud Resources" (Cloud icon)
- "Web Apps" (Globe icon)

Each filter shows count in badge

**Stats Row** (4 small cards):
- Total Assets: 1,247
- Active: 1,203
- Inactive: 44
- At Risk: 23

**Main Table**:
White card with rounded-2xl, full width table

Table columns:
1. **Asset** (name/identifier - bold)
2. **Type** (badge with icon):
   - Domain (Globe icon, blue)
   - IP Address (Network icon, purple)
   - Cloud (Cloud icon, green)
3. **Risk Level** (colored dot + text):
   - Critical (red dot)
   - High (orange dot)
   - Medium (yellow dot)
   - Low (green dot)
4. **Findings** (number)
5. **Last Scan** (relative time)
6. **Status** (badge: Active/Inactive)
7. **Actions** (two buttons):
   - Scan (Play icon)
   - Details (Eye icon)

Mock data (10 rows):
```javascript
[
  {
    asset: 'acme-corp.com',
    type: 'Domain',
    risk: 'High',
    findings: 23,
    lastScan: '2 hours ago',
    status: 'Active'
  },
  {
    asset: '203.0.113.45',
    type: 'IP Address',
    risk: 'Critical',
    findings: 15,
    lastScan: '5 hours ago',
    status: 'Active'
  },
  {
    asset: 'app.acme-corp.com',
    type: 'Domain',
    risk: 'Medium',
    findings: 8,
    lastScan: '1 day ago',
    status: 'Active'
  },
  {
    asset: 'S3: acme-backups',
    type: 'Cloud',
    risk: 'Critical',
    findings: 31,
    lastScan: '3 hours ago',
    status: 'Active'
  },
  {
    asset: 'api.acme-corp.com',
    type: 'Domain',
    risk: 'Low',
    findings: 3,
    lastScan: '6 hours ago',
    status: 'Active'
  },
  {
    asset: '203.0.113.50',
    type: 'IP Address',
    risk: 'Medium',
    findings: 12,
    lastScan: '2 days ago',
    status: 'Active'
  },
  {
    asset: 'dev.acme-corp.com',
    type: 'Domain',
    risk: 'High',
    findings: 19,
    lastScan: '4 hours ago',
    status: 'Active'
  },
  {
    asset: 'EC2: prod-server-01',
    type: 'Cloud',
    risk: 'Low',
    findings: 5,
    lastScan: '1 day ago',
    status: 'Active'
  },
  {
    asset: 'mail.acme-corp.com',
    type: 'Domain',
    risk: 'Medium',
    findings: 7,
    lastScan: '8 hours ago',
    status: 'Inactive'
  },
  {
    asset: '203.0.113.100',
    type: 'IP Address',
    risk: 'Low',
    findings: 2,
    lastScan: '1 week ago',
    status: 'Active'
  }
]
```

**Table Styling**:
- Striped rows (alternate gray background)
- Hover effect on rows (light blue background)
- Badges with rounded-full
- Icon buttons with hover effects

---

### PAGE 3: NEW SCAN (/src/app/pages/recon/NewScan.tsx)

**Header**:
- Title: "Configure New Scan"
- Subtitle: "Set up a new reconnaissance scan"

**Form Layout** (single column, centered, max-w-4xl):

**Card 1 - Scan Configuration**:

**Section: Target Configuration**
- Label: "Scan Targets"
- Textarea input (4 rows)
- Placeholder: "Enter domains, IP addresses, or CIDR ranges (one per line)\nExample:\nacme-corp.com\n203.0.113.0/24\n*.acme-corp.com"
- Help text: "Supports domains, subdomains, IP addresses, and CIDR notation"

**Section: Scan Type**
- Label: "Scan Type"
- Radio button group (3 options in horizontal layout):

1. **Full Scan** (default selected)
   - Icon: Target
   - Description: "Comprehensive scan of all assets and vulnerabilities"
   - Duration: "~2-4 hours"
   - Blue border when selected

2. **Quick Scan**
   - Icon: Zap
   - Description: "Fast scan focusing on critical vulnerabilities"
   - Duration: "~15-30 minutes"

3. **Custom Scan**
   - Icon: Settings
   - Description: "Configure specific scan parameters"
   - Duration: "Variable"

**Section: Scan Options** (checkboxes):
- ☑ Port Scanning
- ☑ SSL/TLS Analysis
- ☑ DNS Enumeration
- ☑ Subdomain Discovery
- ☑ Technology Detection
- ☐ Vulnerability Assessment
- ☐ Screenshot Capture

**Card 2 - Schedule & Notifications**:

**Section: Schedule**
- Label: "Scan Schedule"
- Radio buttons:
  - ● Run immediately (selected)
  - ○ Schedule for later
  
If "Schedule for later" selected, show:
- Date picker
- Time picker

**Section: Notifications**
- Label: "Alert Preferences"
- Checkboxes:
  - ☑ Email on completion
  - ☑ Notify on critical findings
  - ☐ Slack integration
  - ☐ Webhook notification

**Action Buttons** (bottom of form):
- Cancel button (gray, outlined)
- "Start Scan" button (blue gradient, white text, Play icon)

---

## ROUTING CONFIGURATION

**File**: /src/app/routes.tsx

```typescript
import { createBrowserRouter } from 'react-router';
import ReconLayout from './layouts/ReconLayout';
import ReconDashboard from './pages/recon/ReconDashboard';
import AssetInventory from './pages/recon/AssetInventory';
import NewScan from './pages/recon/NewScan';

export const router = createBrowserRouter([
  {
    path: '/',
    Component: ReconLayout,
    children: [
      { index: true, Component: ReconDashboard },
      { path: 'inventory', Component: AssetInventory },
      { path: 'new-scan', Component: NewScan },
    ],
  },
]);
```

---

## APP ENTRY POINT

**File**: /src/app/App.tsx

```typescript
import { RouterProvider } from 'react-router';
import { router } from './routes';

function App() {
  return <RouterProvider router={router} />;
}

export default App;
```

---

## STYLING REQUIREMENTS

### Theme CSS (/src/styles/theme.css)
```css
@import 'tailwindcss';

/* Premium macOS aesthetic tokens */
@theme {
  --color-primary: #3b82f6;
  --radius-lg: 1rem;
  --radius-xl: 1.25rem;
  --radius-2xl: 1.5rem;
}

/* Glass morphism utilities */
.glass {
  @apply backdrop-blur-xl bg-white/70 border border-gray-200/50;
}

/* Smooth transitions */
* {
  @apply transition-all duration-200;
}
```

### Font CSS (/src/styles/fonts.css)
```css
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap');

body {
  font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
}
```

---

## INTERACTIVE BEHAVIORS

### Navigation
- Active route highlighted with blue gradient background
- Smooth transitions between pages
- Hover effects on all interactive elements

### Tables
- Row hover with light background change
- Sortable columns (show sort arrow on hover)
- Action buttons appear on row hover

### Forms
- Focus states with blue border
- Validation on submit
- Disabled state for buttons during submission

### Cards
- Subtle shadow on hover (increase shadow-md to shadow-lg)
- Smooth scale transform on hover (scale-[1.01])

---

## RESPONSIVE BEHAVIOR

- Sidebar: Fixed on desktop, collapsible on mobile
- Tables: Horizontal scroll on mobile
- Charts: Maintain aspect ratio, stack vertically on mobile
- Grid layouts: Adjust columns based on screen size

---

## ICONS FROM LUCIDE-REACT

Use these specific icons:
- Search, Package, Activity, LayoutDashboard (navigation)
- Shield, AlertTriangle, Clock, TrendingUp, TrendingDown (metrics)
- Download, Eye, Play, Settings, Bell (actions)
- Globe, Network, Cloud, Target, Zap (asset types)
- ChevronRight, ChevronDown (arrows)

---

## MOCK DATA REQUIREMENTS

Include realistic mock data for:
- Asset inventory (10+ items)
- Recent scans (5+ items)
- Risk score trends (7 data points)
- Finding distribution (4 severity levels)
- Metric cards (4 with values)

---

## FINAL CHECKLIST

Before completing, ensure:
- ✅ All pages render correctly
- ✅ Navigation works between all routes
- ✅ Active states show properly
- ✅ Charts render with data
- ✅ Tables display with mock data
- ✅ Forms have all fields
- ✅ Glassmorphism effects applied
- ✅ Rounded corners (20px+) everywhere
- ✅ Inter font loaded and applied
- ✅ Smooth transitions on interactions
- ✅ Hover states work
- ✅ Icons display correctly
- ✅ Color scheme is consistent
- ✅ Responsive layout works

---

## DELIVERABLES

Generate a complete, working application with:
1. All components properly structured
2. All pages fully implemented
3. Routing configured and working
4. Styling applied with Tailwind
5. Mock data populated
6. Interactive elements functional
7. Production-ready code quality

This should be a fully functional single-page application ready to connect to a backend API.
