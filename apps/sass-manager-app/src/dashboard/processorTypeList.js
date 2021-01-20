import React from 'react';
import styled from 'styled-components';
import { Droppable} from 'react-beautiful-dnd';
import {
    Divider,
    Typography
} from '@material-ui/core';

import ProcessorType from './processorType';

// TODO: change list to material-ui grid
const List = styled.div`
    flex-grow: 1;
    background-color: ${props => (props.isDraggingOver? 'skyblue': '#F4F4F4')};
    width: 220px;
`;

export default function ProcessorTypeList(props) {
    return (
        <List>
            <Typography variant="subtitle2" component="span">
                Processor Types
            </Typography>
            <Divider />
            <Droppable droppableId={'processorType'} 
                type={'processor'}
                isDropDisabled={true}
                >
                {(provided, snapshot) => (
                    <List 
                        ref={provided.innerRef}
                        {...provided.droppableProps}
                        isDraggingOver={snapshot.isDraggingOver}                            
                    >
                        {props.processorTypeOrder.map((processorType, index) => 
                            <ProcessorType key={processorType} item={props.processorTypes[processorType]} index={index} />)}
                        {provided.placeholder}
                    </List>                       
                )}
            </Droppable>
        </List>
    );
}