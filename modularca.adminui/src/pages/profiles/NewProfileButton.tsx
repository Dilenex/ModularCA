import React from 'react';
import { Link } from 'react-router-dom';
import { PROFILE_TYPES, profileNewPath, type ProfileType } from './profileRoutes';

/** The "New … profile" button on a Profile Management tab; opens that type's create page. */
export const NewProfileButton: React.FC<{ type: ProfileType }> = ({ type }) => (
    <Link to={profileNewPath(type)}
        className="px-4 py-2 text-sm bg-accent text-on-accent rounded hover:bg-accent-hover transition-colors">
        New {PROFILE_TYPES[type].noun}
    </Link>
);

export default NewProfileButton;
