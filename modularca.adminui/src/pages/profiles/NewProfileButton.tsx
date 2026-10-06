import React from 'react';
import { Link } from 'react-router-dom';
import { PROFILE_TYPES, profileNewPath, type ProfileType } from './profileRoutes';

/** The "New … profile" button on a Profile Management tab; opens that type's create page. */
export const NewProfileButton: React.FC<{ type: ProfileType }> = ({ type }) => (
    <Link to={profileNewPath(type)}
        className="px-2.5 py-1 text-xs font-medium rounded border border-accent bg-accent text-on-accent hover:bg-accent-hover transition-colors whitespace-nowrap">
        New {PROFILE_TYPES[type].noun}
    </Link>
);

export default NewProfileButton;
