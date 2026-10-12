import { apiRequest } from './client';
import { ApiUserRole } from './auth';

export type ManagedUser = {
  id: string;
  username: string;
  email: string;
  role: ApiUserRole;
  roles: string[];
  permissions: string[];
  isActive: boolean;
  createdAt: string | null;
};

export type CreateUserPayload = {
  username: string;
  email: string;
  password: string;
  role: 'basic' | 'privileged' | 'admin';
};

export async function getUsers(): Promise<{ users: ManagedUser[] }> {
  return apiRequest<{ users: ManagedUser[] }>('/users');
}

export async function createUser(payload: CreateUserPayload): Promise<{ message: string; user: ManagedUser }> {
  return apiRequest<{ message: string; user: ManagedUser }>('/users', {
    method: 'POST',
    body: payload,
  });
}

export async function deleteUser(userId: string): Promise<{ message: string }> {
  return apiRequest<{ message: string }>(`/users/${userId}`, {
    method: 'DELETE',
  });
}
