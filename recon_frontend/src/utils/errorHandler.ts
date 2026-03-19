import { toast } from 'sonner';

import { ApiError } from '../api/client';

export function handleApiError(error: unknown) {
  if (!(error instanceof ApiError)) {
    toast.error('An unexpected error occurred');
    // eslint-disable-next-line no-console
    console.error('Unexpected error:', error);
    return;
  }

  if (error.status === 0) {
    toast.error('Network error. Please check your connection.');
    return;
  }

  switch (error.status) {
    case 400:
      toast.error(error.message || 'Invalid request');
      break;
    case 401:
      // Token refresh handled by api client; if still 401, caller should redirect.
      if (error.code === 'INVALID_CREDENTIALS') {
        toast.error('Invalid email or password');
      } else {
        toast.error('Authentication required');
      }
      break;
    case 403:
      toast.error('You do not have permission to perform this action');
      break;
    case 404:
      toast.error('Resource not found');
      break;
    case 409:
      toast.error(error.message || 'Conflict occurred');
      break;
    case 422:
      if (error.details?.length) {
        error.details.forEach((detail) => toast.error(`${detail.field}: ${detail.message}`));
      } else {
        toast.error(error.message || 'Validation error');
      }
      break;
    case 429:
      toast.error('Too many requests. Please wait a moment.');
      break;
    case 500:
    case 503:
      toast.error('Server error. Please try again later.');
      // eslint-disable-next-line no-console
      console.error('Server error:', error.payload);
      break;
    default:
      toast.error(error.message || 'An unexpected error occurred');
  }
}
