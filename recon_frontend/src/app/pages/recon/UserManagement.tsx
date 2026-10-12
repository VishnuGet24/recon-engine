import { useEffect, useMemo, useState } from 'react';
import {
  AlertTriangle,
  Check,
  CheckCircle2,
  Eye,
  EyeOff,
  Flame,
  KeyRound,
  Lock,
  Plus,
  RefreshCw,
  Search,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Trash2,
  UserCheck,
  Users,
  X,
  Zap,
} from 'lucide-react';
import { toast } from 'sonner';

import { createUser, deleteUser, getUsers, ManagedUser } from '../../../api/users';
import { formatDateTime } from '../../../utils/date';
import { handleApiError } from '../../../utils/errorHandler';
import { useAuth } from '../../context/AuthContext';

type RoleOption = {
  id: 'basic' | 'privileged' | 'admin';
  name: string;
  badge: string;
  icon: typeof Shield;
  colorClass: string;
  description: string;
  scansAllowed: string;
  canManageUsers: boolean;
};

const ROLE_OPTIONS: RoleOption[] = [
  {
    id: 'basic',
    name: 'Basic User',
    badge: 'Passive Only',
    icon: ShieldCheck,
    colorClass: 'border-amber-200 bg-amber-50/50 hover:border-amber-400 text-amber-900',
    description: 'Restricted account for routine asset discovery. Active & Full scanning are locked.',
    scansAllowed: 'Passive scans only (Active & Full locked)',
    canManageUsers: false,
  },
  {
    id: 'privileged',
    name: 'Privileged User',
    badge: 'All Scans Unlocked',
    icon: Zap,
    colorClass: 'border-blue-200 bg-blue-50/50 hover:border-blue-400 text-blue-900',
    description: 'Full scanning privileges. Can run passive, active port/service probing, and full engine scans.',
    scansAllowed: 'Passive, Active, and Full scans unlocked',
    canManageUsers: false,
  },
  {
    id: 'admin',
    name: 'Administrator',
    badge: 'Full Authority',
    icon: ShieldAlert,
    colorClass: 'border-purple-200 bg-purple-50/50 hover:border-purple-400 text-purple-900',
    description: 'Superuser account. Full scanning access plus exclusive rights to provision and manage users.',
    scansAllowed: 'All scans + User Management',
    canManageUsers: true,
  },
];

export default function UserManagement() {
  const { user: currentUser } = useAuth();
  const [users, setUsers] = useState<ManagedUser[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState('');
  const [roleFilter, setRoleFilter] = useState<'all' | 'admin' | 'privileged' | 'basic'>('all');

  // Modal State
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [newUsername, setNewUsername] = useState('');
  const [newEmail, setNewEmail] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [newRole, setNewRole] = useState<'basic' | 'privileged' | 'admin'>('basic');
  const [showPassword, setShowPassword] = useState(false);
  const [creating, setCreating] = useState(false);

  // Delete Confirm State
  const [userToDelete, setUserToDelete] = useState<ManagedUser | null>(null);
  const [deleting, setDeleting] = useState(false);

  const fetchUsers = async () => {
    try {
      setLoading(true);
      const res = await getUsers();
      setUsers(Array.isArray(res.users) ? res.users : []);
    } catch (err) {
      handleApiError(err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void fetchUsers();
  }, []);

  const filteredUsers = useMemo(() => {
    return users.filter((u) => {
      const matchesSearch =
        u.username.toLowerCase().includes(searchQuery.toLowerCase()) ||
        u.email.toLowerCase().includes(searchQuery.toLowerCase());
      const matchesRole = roleFilter === 'all' || u.role === roleFilter;
      return matchesSearch && matchesRole;
    });
  }, [users, searchQuery, roleFilter]);

  const stats = useMemo(() => {
    const total = users.length;
    const admins = users.filter((u) => u.role === 'admin').length;
    const privileged = users.filter((u) => u.role === 'privileged' || u.role === 'operator').length;
    const basic = users.filter((u) => u.role === 'basic' || u.role === 'viewer').length;
    return { total, admins, privileged, basic };
  }, [users]);

  const handleCreateUser = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newUsername.trim() || !newEmail.trim() || !newPassword) {
      toast.error('All fields are required');
      return;
    }
    if (newPassword.length < 8) {
      toast.error('Password must be at least 8 characters long');
      return;
    }

    try {
      setCreating(true);
      const res = await createUser({
        username: newUsername.trim(),
        email: newEmail.trim().toLowerCase(),
        password: newPassword,
        role: newRole,
      });

      toast.success(res.message || `User ${res.user.username} created successfully`);
      setIsModalOpen(false);
      setNewUsername('');
      setNewEmail('');
      setNewPassword('');
      setNewRole('basic');
      await fetchUsers();
    } catch (err) {
      handleApiError(err);
    } finally {
      setCreating(false);
    }
  };

  const handleDeleteUser = async () => {
    if (!userToDelete) return;
    try {
      setDeleting(true);
      const res = await deleteUser(userToDelete.id);
      toast.success(res.message || `User ${userToDelete.username} deleted`);
      setUserToDelete(null);
      await fetchUsers();
    } catch (err) {
      handleApiError(err);
    } finally {
      setDeleting(false);
    }
  };

  const getRoleBadge = (role: string) => {
    switch (role) {
      case 'admin':
        return (
          <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-semibold bg-purple-100 text-purple-800 border border-purple-200">
            <ShieldAlert className="w-3.5 h-3.5" />
            Administrator
          </span>
        );
      case 'privileged':
      case 'operator':
        return (
          <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-semibold bg-blue-100 text-blue-800 border border-blue-200">
            <Zap className="w-3.5 h-3.5" />
            Privileged User
          </span>
        );
      case 'basic':
      case 'viewer':
      default:
        return (
          <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-semibold bg-amber-100 text-amber-800 border border-amber-200">
            <ShieldCheck className="w-3.5 h-3.5" />
            Basic User
          </span>
        );
    }
  };

  if (currentUser && currentUser.role !== 'admin') {
    return (
      <div className="p-12 max-w-xl mx-auto text-center space-y-4">
        <div className="w-16 h-16 rounded-2xl bg-red-100 text-red-600 flex items-center justify-center mx-auto">
          <ShieldAlert className="w-8 h-8" />
        </div>
        <h2 className="text-xl font-bold text-gray-900">Access Restricted</h2>
        <p className="text-sm text-gray-600">
          User Management is strictly restricted to Administrators. Your account does not have sufficient permissions to view or provision user accounts.
        </p>
      </div>
    );
  }

  return (
    <div className="p-8 max-w-7xl mx-auto space-y-8">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4">
        <div>
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-purple-500 to-indigo-600 flex items-center justify-center text-white shadow-md shadow-indigo-500/20">
              <Users className="w-5 h-5" />
            </div>
            <div>
              <h1 className="text-2xl font-bold text-gray-900">User Management</h1>
              <p className="text-sm text-gray-500">
                Provision users and enforce scanning privileges (Administrator Authority)
              </p>
            </div>
          </div>
        </div>

        <div className="flex items-center gap-3">
          <button
            type="button"
            onClick={() => void fetchUsers()}
            disabled={loading}
            className="flex items-center gap-2 px-4 py-2.5 rounded-xl border border-gray-200 bg-white text-gray-700 hover:bg-gray-50 text-sm font-medium transition-all shadow-sm"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
            Refresh
          </button>
          <button
            type="button"
            onClick={() => setIsModalOpen(true)}
            className="flex items-center gap-2 px-5 py-2.5 rounded-xl bg-gradient-to-r from-blue-600 to-indigo-600 text-white font-medium text-sm hover:shadow-lg hover:shadow-blue-500/25 transition-all shadow-sm"
          >
            <Plus className="w-4 h-4" />
            Create User
          </button>
        </div>
      </div>

      {/* Metric Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="bg-white rounded-2xl p-5 border border-gray-100 shadow-sm flex items-center justify-between">
          <div>
            <p className="text-xs font-medium text-gray-500 uppercase tracking-wider">Total Accounts</p>
            <p className="text-2xl font-bold text-gray-900 mt-1">{stats.total}</p>
          </div>
          <div className="w-12 h-12 rounded-xl bg-gray-50 flex items-center justify-center text-gray-600">
            <Users className="w-6 h-6" />
          </div>
        </div>

        <div className="bg-white rounded-2xl p-5 border border-purple-100 shadow-sm flex items-center justify-between">
          <div>
            <p className="text-xs font-medium text-purple-600 uppercase tracking-wider">Administrators</p>
            <p className="text-2xl font-bold text-purple-900 mt-1">{stats.admins}</p>
            <span className="text-[11px] text-gray-400">Full Access + User Mgmt</span>
          </div>
          <div className="w-12 h-12 rounded-xl bg-purple-50 flex items-center justify-center text-purple-600">
            <ShieldAlert className="w-6 h-6" />
          </div>
        </div>

        <div className="bg-white rounded-2xl p-5 border border-blue-100 shadow-sm flex items-center justify-between">
          <div>
            <p className="text-xs font-medium text-blue-600 uppercase tracking-wider">Privileged Users</p>
            <p className="text-2xl font-bold text-blue-900 mt-1">{stats.privileged}</p>
            <span className="text-[11px] text-gray-400">Passive, Active & Full</span>
          </div>
          <div className="w-12 h-12 rounded-xl bg-blue-50 flex items-center justify-center text-blue-600">
            <Zap className="w-6 h-6" />
          </div>
        </div>

        <div className="bg-white rounded-2xl p-5 border border-amber-100 shadow-sm flex items-center justify-between">
          <div>
            <p className="text-xs font-medium text-amber-600 uppercase tracking-wider">Basic Users</p>
            <p className="text-2xl font-bold text-amber-900 mt-1">{stats.basic}</p>
            <span className="text-[11px] text-gray-400">Passive Only (Locked)</span>
          </div>
          <div className="w-12 h-12 rounded-xl bg-amber-50 flex items-center justify-center text-amber-600">
            <Lock className="w-6 h-6" />
          </div>
        </div>
      </div>

      {/* Role Policy Summary Banner */}
      <div className="bg-gradient-to-r from-blue-50/80 via-indigo-50/50 to-purple-50/80 border border-blue-100 rounded-2xl p-5 shadow-sm">
        <h4 className="text-sm font-semibold text-gray-900 mb-2 flex items-center gap-2">
          <KeyRound className="w-4 h-4 text-indigo-600" />
          Role-Based Access Control (RBAC) Governance Matrix
        </h4>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs mt-3">
          <div className="bg-white/80 p-3.5 rounded-xl border border-amber-200">
            <div className="flex items-center gap-2 font-semibold text-amber-900 mb-1">
              <ShieldCheck className="w-4 h-4 text-amber-600" />
              Basic User
            </div>
            <p className="text-gray-600">
              Authorized strictly for <strong>Passive Scans</strong> (DNS, WHOIS, Subdomain Enum). Active Port Scanning and Full Engine Scans are <strong>locked</strong>.
            </p>
          </div>
          <div className="bg-white/80 p-3.5 rounded-xl border border-blue-200">
            <div className="flex items-center gap-2 font-semibold text-blue-900 mb-1">
              <Zap className="w-4 h-4 text-blue-600" />
              Privileged User
            </div>
            <p className="text-gray-600">
              Authorized for <strong>Passive, Active, and Full Scans</strong>. Does not have permission to create or manage other users.
            </p>
          </div>
          <div className="bg-white/80 p-3.5 rounded-xl border border-purple-200">
            <div className="flex items-center gap-2 font-semibold text-purple-900 mb-1">
              <ShieldAlert className="w-4 h-4 text-purple-600" />
              Administrator
            </div>
            <p className="text-gray-600">
              Holds complete operational access. The <strong>only</strong> role empowered to provision new users and assign security tiers.
            </p>
          </div>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="bg-white rounded-2xl p-4 border border-gray-100 shadow-sm flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div className="relative flex-1 max-w-md">
          <Search className="w-4 h-4 text-gray-400 absolute left-3.5 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            placeholder="Search by username or email..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full pl-10 pr-4 py-2 text-sm border border-gray-200 rounded-xl focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
          />
        </div>

        <div className="flex items-center gap-2">
          <span className="text-xs text-gray-500 font-medium mr-1">Filter Role:</span>
          {(['all', 'admin', 'privileged', 'basic'] as const).map((r) => (
            <button
              key={r}
              type="button"
              onClick={() => setRoleFilter(r)}
              className={`px-3 py-1.5 rounded-lg text-xs font-medium capitalize transition-all ${
                roleFilter === r
                  ? 'bg-blue-600 text-white shadow-sm'
                  : 'bg-gray-100 text-gray-600 hover:bg-gray-200'
              }`}
            >
              {r}
            </button>
          ))}
        </div>
      </div>

      {/* Users Table */}
      <div className="bg-white rounded-2xl border border-gray-100 shadow-sm overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead className="bg-gray-50/80 border-b border-gray-100 text-gray-500 font-medium text-xs">
              <tr>
                <th className="py-3.5 px-6">User Account</th>
                <th className="py-3.5 px-6">Role</th>
                <th className="py-3.5 px-6">Scan Permissions</th>
                <th className="py-3.5 px-6">User Mgmt</th>
                <th className="py-3.5 px-6">Date Created</th>
                <th className="py-3.5 px-6 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100 text-gray-700">
              {loading ? (
                <tr>
                  <td colSpan={6} className="py-12 text-center text-gray-500">
                    <RefreshCw className="w-6 h-6 animate-spin mx-auto text-blue-500 mb-2" />
                    Loading user accounts...
                  </td>
                </tr>
              ) : filteredUsers.length === 0 ? (
                <tr>
                  <td colSpan={6} className="py-12 text-center text-gray-500">
                    <Users className="w-8 h-8 mx-auto text-gray-300 mb-2" />
                    No users matching criteria.
                  </td>
                </tr>
              ) : (
                filteredUsers.map((u) => {
                  const isCurrent = String(u.id) === String(currentUser?.id);
                  const isUserAdmin = u.role === 'admin';
                  const isUserPrivileged = u.role === 'privileged' || u.role === 'operator';

                  return (
                    <tr key={u.id} className="hover:bg-gray-50/60 transition-colors">
                      <td className="py-4 px-6">
                        <div className="flex items-center gap-3">
                          <div className="w-9 h-9 rounded-full bg-gradient-to-tr from-blue-500 to-indigo-600 text-white flex items-center justify-center font-bold text-sm shadow-sm">
                            {u.username.charAt(0).toUpperCase()}
                          </div>
                          <div>
                            <div className="font-semibold text-gray-900 flex items-center gap-2">
                              {u.username}
                              {isCurrent ? (
                                <span className="text-[10px] bg-blue-100 text-blue-800 font-semibold px-2 py-0.5 rounded-full">
                                  You
                                </span>
                              ) : null}
                            </div>
                            <p className="text-xs text-gray-500">{u.email}</p>
                          </div>
                        </div>
                      </td>

                      <td className="py-4 px-6">{getRoleBadge(u.role)}</td>

                      <td className="py-4 px-6">
                        {isUserAdmin ? (
                          <span className="text-xs text-purple-700 font-medium">All Scans (Passive, Active, Full)</span>
                        ) : isUserPrivileged ? (
                          <span className="text-xs text-blue-700 font-medium">Passive, Active, and Full</span>
                        ) : (
                          <span className="text-xs text-amber-700 font-medium flex items-center gap-1">
                            <Lock className="w-3 h-3" /> Passive Only (Active/Full locked)
                          </span>
                        )}
                      </td>

                      <td className="py-4 px-6">
                        {isUserAdmin ? (
                          <span className="inline-flex items-center gap-1 text-xs text-emerald-700 font-medium">
                            <Check className="w-3.5 h-3.5" /> Can create users
                          </span>
                        ) : (
                          <span className="inline-flex items-center gap-1 text-xs text-gray-400">
                            <X className="w-3.5 h-3.5" /> No authority
                          </span>
                        )}
                      </td>

                      <td className="py-4 px-6 text-xs text-gray-500">
                        {u.createdAt ? formatDateTime(u.createdAt) : '—'}
                      </td>

                      <td className="py-4 px-6 text-right">
                        {isCurrent ? (
                          <span className="text-xs text-gray-400 italic">Protected</span>
                        ) : (
                          <button
                            type="button"
                            onClick={() => setUserToDelete(u)}
                            className="p-2 text-gray-400 hover:text-red-600 rounded-lg hover:bg-red-50 transition-colors"
                            title="Delete user"
                          >
                            <Trash2 className="w-4 h-4" />
                          </button>
                        )}
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Create User Modal */}
      {isModalOpen ? (
        <div className="fixed inset-0 z-50 bg-black/50 backdrop-blur-sm flex items-center justify-center p-4 overflow-y-auto">
          <div className="bg-white rounded-3xl max-w-xl w-full shadow-2xl border border-gray-100 overflow-hidden animate-in fade-in zoom-in-95 duration-200">
            <div className="p-6 border-b border-gray-100 flex items-center justify-between">
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 rounded-xl bg-blue-100 text-blue-600 flex items-center justify-center">
                  <UserCheck className="w-5 h-5" />
                </div>
                <div>
                  <h3 className="text-lg font-bold text-gray-900">Create New User</h3>
                  <p className="text-xs text-gray-500">Assign role credentials and scanning permissions</p>
                </div>
              </div>
              <button
                type="button"
                onClick={() => setIsModalOpen(false)}
                className="text-gray-400 hover:text-gray-600 p-2 rounded-lg"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <form onSubmit={handleCreateUser} className="p-6 space-y-5">
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div>
                  <label className="block text-xs font-semibold text-gray-700 uppercase mb-1.5">
                    Username
                  </label>
                  <input
                    type="text"
                    required
                    value={newUsername}
                    onChange={(e) => setNewUsername(e.target.value)}
                    placeholder="e.g. security_analyst"
                    className="w-full px-3.5 py-2.5 text-sm border border-gray-200 rounded-xl focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                  />
                </div>

                <div>
                  <label className="block text-xs font-semibold text-gray-700 uppercase mb-1.5">
                    Email Address
                  </label>
                  <input
                    type="email"
                    required
                    value={newEmail}
                    onChange={(e) => setNewEmail(e.target.value)}
                    placeholder="analyst@domain.com"
                    className="w-full px-3.5 py-2.5 text-sm border border-gray-200 rounded-xl focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                  />
                </div>
              </div>

              <div>
                <label className="block text-xs font-semibold text-gray-700 uppercase mb-1.5">
                  Password (min. 8 characters)
                </label>
                <div className="relative">
                  <input
                    type={showPassword ? 'text' : 'password'}
                    required
                    minLength={8}
                    value={newPassword}
                    onChange={(e) => setNewPassword(e.target.value)}
                    placeholder="Strong account password"
                    className="w-full pl-3.5 pr-10 py-2.5 text-sm border border-gray-200 rounded-xl focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                  />
                  <button
                    type="button"
                    onClick={() => setShowPassword(!showPassword)}
                    className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-400 hover:text-gray-600"
                  >
                    {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                  </button>
                </div>
              </div>

              {/* Role Selection */}
              <div>
                <label className="block text-xs font-semibold text-gray-700 uppercase mb-2">
                  Select Role & Access Level
                </label>
                <div className="space-y-3">
                  {ROLE_OPTIONS.map((opt) => {
                    const Icon = opt.icon;
                    const isSelected = newRole === opt.id;
                    return (
                      <div
                        key={opt.id}
                        onClick={() => setNewRole(opt.id)}
                        className={`p-4 rounded-xl border-2 cursor-pointer transition-all ${
                          isSelected
                            ? 'border-blue-600 bg-blue-50/70 shadow-sm'
                            : 'border-gray-200 bg-white hover:border-gray-300'
                        }`}
                      >
                        <div className="flex items-center justify-between mb-1.5">
                          <div className="flex items-center gap-2.5">
                            <Icon className={`w-4 h-4 ${isSelected ? 'text-blue-600' : 'text-gray-500'}`} />
                            <span className="font-semibold text-sm text-gray-900">{opt.name}</span>
                          </div>
                          <span
                            className={`text-[11px] font-semibold px-2 py-0.5 rounded-full ${
                              opt.id === 'admin'
                                ? 'bg-purple-100 text-purple-800'
                                : opt.id === 'privileged'
                                ? 'bg-blue-100 text-blue-800'
                                : 'bg-amber-100 text-amber-800'
                            }`}
                          >
                            {opt.badge}
                          </span>
                        </div>
                        <p className="text-xs text-gray-600 mb-1">{opt.description}</p>
                        <p className="text-[11px] font-medium text-gray-500">
                          <strong>Scan Access:</strong> {opt.scansAllowed}
                        </p>
                      </div>
                    );
                  })}
                </div>
              </div>

              {/* Action Buttons */}
              <div className="flex items-center justify-end gap-3 pt-4 border-t border-gray-100">
                <button
                  type="button"
                  onClick={() => setIsModalOpen(false)}
                  disabled={creating}
                  className="px-4 py-2.5 rounded-xl border border-gray-200 text-sm font-medium text-gray-700 hover:bg-gray-50 transition-colors"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={creating}
                  className="px-6 py-2.5 rounded-xl bg-gradient-to-r from-blue-600 to-indigo-600 text-white text-sm font-semibold hover:shadow-lg hover:shadow-blue-500/25 transition-all disabled:opacity-60 flex items-center gap-2"
                >
                  {creating ? (
                    <>
                      <RefreshCw className="w-4 h-4 animate-spin" />
                      Creating User...
                    </>
                  ) : (
                    'Create User'
                  )}
                </button>
              </div>
            </form>
          </div>
        </div>
      ) : null}

      {/* Delete Confirmation Modal */}
      {userToDelete ? (
        <div className="fixed inset-0 z-50 bg-black/50 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-white rounded-3xl max-w-md w-full p-6 shadow-2xl border border-gray-100 animate-in fade-in zoom-in-95">
            <div className="w-12 h-12 rounded-2xl bg-red-100 text-red-600 flex items-center justify-center mb-4">
              <AlertTriangle className="w-6 h-6" />
            </div>
            <h3 className="text-lg font-bold text-gray-900 mb-1">Delete User Account</h3>
            <p className="text-sm text-gray-600 mb-6">
              Are you sure you want to delete user <strong className="text-gray-900">{userToDelete.username}</strong> ({userToDelete.email})? This action cannot be undone.
            </p>
            <div className="flex items-center justify-end gap-3">
              <button
                type="button"
                onClick={() => setUserToDelete(null)}
                disabled={deleting}
                className="px-4 py-2 rounded-xl border border-gray-200 text-sm font-medium text-gray-700 hover:bg-gray-50"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={handleDeleteUser}
                disabled={deleting}
                className="px-5 py-2 rounded-xl bg-red-600 text-white text-sm font-semibold hover:bg-red-700 shadow-sm disabled:opacity-60 flex items-center gap-2"
              >
                {deleting ? 'Deleting...' : 'Confirm Delete'}
              </button>
            </div>
          </div>
        </div>
      ) : null}
    </div>
  );
}
