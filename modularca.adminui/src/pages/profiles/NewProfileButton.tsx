import React from 'react';
import { Link } from 'react-router-dom';
import { toolbarButtonPrimary } from '@shared/components/actionButtons';
import { PROFILE_TYPES, profileNewPath, type ProfileType } from './profileRoutes';

/** The "+ New" button on a Profile Management tab; opens that type's create page. */
export const NewProfileButton: React.FC<{ type: ProfileType }> = ({ type }) => (
    <Link to={profileNewPath(type)} className={toolbarButtonPrimary} title={`New ${PROFILE_TYPES[type].noun}`} aria-label={`New ${PROFILE_TYPES[type].noun}`}>
        + New
    </Link>
);

export default NewProfileButton;
