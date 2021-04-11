import React from 'react';
import {
    Button,
    Dialog,
    DialogTitle,
    DialogContent,
    DialogContentText,
    DialogActions,
    Typography
} from '@material-ui/core';

export default function ConfirmDialog({
    open,
    text,
    handleDialogCancel,
    handleDialogConfirm
})
{
    return(
        <Dialog
            open={open}
            onClose={handleDialogCancel}
            aria-labelledby='alert-dialog-title'
            aria-describedby='alert-dialog-description'
        >
            {/* <DialogTitle id='alert-dialog-title'><Typography variant="subtitle1" component="span">{title}</Typography></DialogTitle> */}
            <DialogContent>
                <DialogContentText id='alert-dialog-description'>
                    <Typography color="textSecondary">
                        {text}
                    </Typography>
                </DialogContentText>
            </DialogContent>
            <DialogActions>
                <Button onClick={handleDialogCancel} color='primary'>
                    Cancel
                </Button>
                <Button onClick={handleDialogConfirm} color='primary' autoFocus>
                    Confirm
                </Button>
            </DialogActions>
        </Dialog>
    );
}