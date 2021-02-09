import React from 'react';
import {
    Box,
    Typography,
    Link
} from '@material-ui/core';

export default function Footer() {
    return (
        <Box pt={4}>
            <Typography variant='body2' color='textSecondary' align='center'>
                {'Copyright © '}
                <Link color='inherit' href='https://sec.ethz.ch/'>
                    Singapore ETH Centre
        </Link>{' '}
                {new Date().getFullYear()}
                {'.'}
            </Typography>
        </Box>
    );
}