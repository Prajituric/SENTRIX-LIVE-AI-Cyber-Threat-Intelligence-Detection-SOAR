import React from 'react';
import { NavLink } from 'react-router-dom';
import { ListItem, ListItemButton, ListItemIcon, ListItemText } from '@mui/material';

function NavigationItem({ to, icon, text }) {
  return (
    <ListItem disablePadding>
      <ListItemButton
        component={NavLink}
        to={to}
        sx={{
          '&.active': {
            backgroundColor: 'rgba(144, 202, 249, 0.2)',
          },
        }}
      >
        <ListItemIcon>{icon}</ListItemIcon>
        <ListItemText primary={text} />
      </ListItemButton>
    </ListItem>
  );
}

export default NavigationItem;