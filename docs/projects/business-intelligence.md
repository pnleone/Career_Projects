# Business Intelligence & Data Analytics

<img src="/Career_Projects/assets/misc/bi-logo.png" alt="BI-Logo">

End-to-end BI implementation demonstrating data engineering, modeling, and visualization capabilities. Multi-platform architecture spanning SQL Server, Excel Power Query, and Power BI with advanced DAX time intelligence and relational integrity controls.

**Technologies:** SQL Server 2022 Express, Excel Power Query, Power BI Desktop, DAX
    
 

**Skills Matrix**

| Category | Technologies Used | Proficiency Demonstrated |
|----------|-------------------|-------------------------|
| Data Engineering | SQL Server, Power Query ETL | Data modeling, normalization, index optimization |
| Business Intelligence | Power BI, Excel Pivot Tables | Dashboard design, DAX, time intelligence |
| Data Visualization | Power BI visuals, Excel charts | KPI design, interactive filtering, drill-through |
| Programming | DAX, SQL, M (Power Query) | Measure creation, query optimization, data transformation |
---

## Project Overview

Developed comprehensive BI solution using Foodmart sample dataset to demonstrate enterprise-grade data analysis capabilities. Implemented multi-tier architecture with data warehouse design, dimensional modeling, and advanced analytics through DAX measures.

**Key Deliverables:**

- Normalized relational database (SQL Server 2022 Express)
- Excel Power Query ETL pipeline with data model
- Interactive Power BI dashboards with time intelligence
- Advanced DAX measures (MTD/QTD/YTD calculations)

---

## Technical Implementation

### Data Architecture

**Dataset Scope:**

- **8 tables** (5 dimension lookups, 3 fact tables)
- **1997-1998** transaction data (269.7K transactions)
- **Dimensional model** with star schema design

**Source Tables:**

- **Dimension Tables:** Customers, Products, Regions, Stores, Calendar
- **Fact Tables:** Transactions_1997, Transactions_1998, Returns_1997-1998

<div class="two-col-right">
  <div class="text-col">
    <h4>Data Model Relationships</h4>
    <p>
      Implemented star schema with proper cardinality (1:M), referential integrity via foreign keys, and bidirectional filtering where appropriate. Hidden foreign keys in Excel model for clean visualization while maintaining relationship functionality.
    </p>
    <p>
      <strong>Key Features:</strong> Calculated columns, custom measures, date hierarchies (Year > Quarter > Month > Day), role-playing dimensions (Calendar table).
    </p>
  </div>
  <div class="image-col">
    <figure>
      <img src="/Career_Projects/assets/screenshots/bi-excel-rel.png" alt="Excel Data Model">
      <figcaption>Excel Data Model Relationships</figcaption>
    </figure>
  </div>
</div>

---

### ETL Pipeline (Power Query)

**Transformation Workflow:**
```
CSV Import → Data Profiling → Type Conversion → Calculated Columns → Table Merge → Load
```

**Key Transformations:**

1. **Calendar Enhancement**
   - Original: Single date column
   - Enhanced: Day, Month, Year, Quarter, Fiscal Period, End-of-Month, Weekend/Weekday indicators
   - Purpose: Enable time intelligence analysis

2. **Transaction Consolidation**
   - Merged 1997/1998 transaction tables
   - Standardized data types across years
   - Added calculated columns: Net Revenue, Transaction Month, Quarter

3. **Data Quality**
   - Removed duplicates (0.2% of dataset)
   - Handled null values in Product_Name (filled from Product_ID lookup)
   - Validated foreign key relationships (100% referential integrity)

<div class="two-col-right">
  <div class="text-col">
    <h4>Calendar Dimension Before/After</h4>
    <p>
      <strong>Original:</strong> Basic short date field only.
    </p>
    <p>
      <strong>Enhanced:</strong> Full date hierarchy with fiscal periods, end-of-period markers, and day-type classification for advanced temporal analysis.
    </p>
  </div>
  <div class="image-col">
    <figure>
      <img src="/Career_Projects/assets/screenshots/bi-excel-cal.png" alt="Calendar Table Transformation">
      <figcaption>Calendar Table Enhancement</figcaption>
    </figure>
  </div>
</div>

---

### SQL Server Implementation

**Database Design:**

- **RDBMS:** SQL Server 2022 Express
- **Schema:** Normalized star schema (3NF dimension tables, denormalized fact tables)
- **Keys:** Clustered indexes on primary keys, non-clustered on foreign keys
- **Constraints:** FK constraints enforce referential integrity

**Database Diagram:**

<figure>
  <img src="/Career_Projects/assets/diagrams/bi-sql-rel.png" alt="SQL Server Database Diagram" class="image-large">
  <figcaption>SQL Server 2022 Database Relationships</figcaption>
</figure>

**Query Example:**

Demonstrates INNER JOIN syntax across 4 tables with date filtering. Query retrieves transaction details with enriched customer, product, and store attributes.
```sql
USE Foodmart
GO

SELECT

	[dbo].[Transactions].[transaction_date]
	,[dbo].[Transactions].[quantity] as "Product QTY"
	,[dbo].[Product_Lookup].[product_name] as "Product"
	,[dbo].[Customer_Lookup].[first_name] as "Customer First Name"
	,[dbo].[Customer_Lookup].[last_name] as "Customer Last Name"
	,[dbo].[Customer_Lookup].[customer_acct_num]
	,[dbo].[Store_Lookup].[store_name]
	,[dbo].[Store_Lookup].[store_city]
	,[dbo].[Store_Lookup].[store_state]
	
FROM [dbo].[Transactions] Inner Join [dbo].[Customer_Lookup] 
ON [dbo].[Transactions].[customer_id] = [dbo].[Customer_Lookup].[customer_id]

Join [dbo].[Store_Lookup]
ON [dbo].[Transactions].[store_id] = [dbo].[Store_Lookup].[store_id]

Join [dbo].[Product_Lookup]
On [dbo].[Transactions].[product_id] = [dbo].[Product_Lookup].[product_id]

Where Year(transaction_date) = 1998 AND Month(transaction_date) = 1 AND Day(transaction_date) = 3
ORDER BY [dbo].[Store_Lookup].[store_city] DESC
GO
```

## Analytics & Visualization

### Excel Pivot Analysis

**Metrics Implemented:**

- **Net Revenue:** `= [Total Transactions] - [Total Returns]`
- **Transaction %:** `= [Region Transactions] / [Total Transactions]`
- **Return Rate:** `= [Returns] / [Total Transactions]`

<div class="two-col-right">
  <div class="text-col">
    <h4>Regional Performance Analysis</h4>
    <p>
      Pivot table with slicer-based filtering (Region, Quarter) and timeline control for QTD analysis. Bar chart visualizes net revenue and transaction distribution across sales regions.
    </p>
    <p>
      <strong>Features:</strong> Dynamic slicers, timeline filters, conditional formatting, drill-through to transaction details.
    </p>
  </div>
  <div class="image-col">
    <figure>
      <img src="/Career_Projects/assets/screenshots/bi-excel-reg.png" alt="Regional Pivot Analysis">
      <figcaption>Regional Performance Pivot Table</figcaption>
    </figure>
  </div>
</div>

---

### DAX Time Intelligence

**Custom Measures:**
```dax
MTD Revenue = 
CALCULATE(
    SUM(Transactions[revenue]),
    DATESMTD('Calendar'[date])
)

QTD Revenue = 
CALCULATE(
    SUM(Transactions[revenue]),
    DATESQTD('Calendar'[date])
)

YTD Revenue = 
CALCULATE(
    SUM(Transactions[revenue]),
    DATESYTD('Calendar'[date])
)

Total Transactions = COUNTROWS(Transactions)

% of Total = 
DIVIDE(
    [Total Transactions],
    CALCULATE([Total Transactions], ALL(Transactions))
)
```

<div class="two-col-right">
  <div class="text-col">
    <h4>Time Intelligence Dashboard</h4>
    <p>
      Pivot table with Year/Quarter slicers showing MTD, QTD, YTD metrics alongside total transactions. Dynamic chart updates based on slicer selections.
    </p>
    <p>
      <strong>Use Case:</strong> Trend analysis, period-over-period comparison, seasonality detection.
    </p>
  </div>
  <div class="image-col">
    <figure>
      <img src="/Career_Projects/assets/screenshots/bi-excel-cal.png" alt="Time Intelligence Pivot">
      <figcaption>DAX Time Intelligence Measures</figcaption>
    </figure>
  </div>
</div>

---

### Power BI Dashboards

#### Main Dashboard

**KPIs:**

- Total Transactions: 269.7K
- Total Returns: 5.65K (2.1% return rate)
- Net Revenue: $1.19M
- Total Revenue: $1.2M

**Visualizations:**

1. **Transactions by Country** (Line Chart)
   - MTD/QTD/YTD trendlines for USA, Mexico, Canada
   - Drill-down to state/city level

2. **Transaction % by Region** (Bar Chart)
   - Horizontal bars ranked by volume
   - Top performer: North West (21.3%)

3. **Revenue by Quarter** (Pie Chart)
   - Q2/Q4 peak seasons ($326.4K each)
   - Q3 low season ($290.9K)

4. **Regional Detail Table**
   - City/State/Country hierarchy
   - Transaction percentage distribution

<figure>
  <img src="/Career_Projects/assets/diagrams/bi-powerbi-main.png" alt="Power BI Main Dashboard" class="image-large">
  <figcaption>Power BI Main Dashboard</figcaption>
</figure>

**Filters:** Year (1996-1998), Quarter (Q1-Q4), Country (Canada, Mexico, USA)

---

#### Product Dashboard

**Operational Metrics:**

- **Stores:** 24
- **Customers:** 1,648
- **Return Rate:** 1.0%
- **Products:** 1,560 SKUs
- **Manufacturers:** 111
- **Avg Retail Price:** $2.12

**Pricing Tier Analysis:**

| Tier | Avg Cost | Retail Price | Margin |
|------|----------|--------------|--------|
| Low | $0.52 | $1.30 | 150% |
| Medium | $1.02 | $2.55 | 150% |
| High | $1.46 | $3.56 | 144% |

**Regional Performance Table:**

- Columns: Manufacturer, Product Name, Qty Sold, Transactions, Total Revenue
- Sort: Descending by Total Revenue
- Drill-through: Product-level transaction details

<figure>
  <img src="/Career_Projects/assets/diagrams/bi-powerbi-product.png" alt="Power BI Product Dashboard" class="image-large">
  <figcaption>Power BI Product Analytics Dashboard</figcaption>
</figure>

**Regional Breakdown:**

- **North West:** 130K transactions, 400K units sold
- **Mexico Central:** 157K transactions, 50K units sold
- Additional regions: South West, Canada West, Mexico South

